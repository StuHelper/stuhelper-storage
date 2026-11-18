package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/sdk"
)

type summaryOnlyAuthorizer struct {
	base   storage.Authorizer
	viewer storage.Principal
}

func (a summaryOnlyAuthorizer) Authorize(ctx context.Context, p storage.Principal, action, id string, protection storage.Protection) error {
	if p == a.viewer {
		if action == "storage.contributions.summary" {
			return nil
		}
		return storage.ErrDenied
	}
	return a.base.Authorize(ctx, p, action, id, protection)
}

type summaryTokenAuth struct{}

func (summaryTokenAuth) Authenticate(r *http.Request) (storage.Principal, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer viewer":
		return storage.Principal{Issuer: "test-issuer", Subject: "viewer"}, nil
	case "Bearer operator":
		return storage.Principal{Issuer: "test-issuer", Subject: "operator"}, nil
	default:
		return storage.Principal{}, storage.ErrDenied
	}
}

func TestContributionTransparencySummaryLeastPrivilegeAndAggregation(t *testing.T) {
	h := harnessFor(t)
	h.provider.verificationClock = h.clock.Now
	viewer := storage.Principal{Issuer: "test-issuer", Subject: "viewer"}
	svc, err := storage.New(h.repo, summaryOnlyAuthorizer{base: h.auth, viewer: viewer}, h.provider, h.provider, storage.Config{
		Clock:              h.clock.Now,
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: t.TempDir(),
		ParallelTransfers:  4,
		Lease:              time.Minute,
		VerificationAge:    time.Hour,
		MaxAttempts:        3,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	handler, err := httpapi.New(svc, summaryTokenAuth{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	viewerClient, err := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer viewer")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	// Viewer cannot read global operations, only community contribution summary.
	opsDenied, err := viewerClient.StorageOperationsWithResponse(h.ctx, nil)
	if err != nil || opsDenied.StatusCode() != http.StatusForbidden {
		t.Fatalf("summary-only viewer gained operations access: %d", opsDenied.StatusCode())
	}

	// Empty state returns idle.
	idleResp, err := viewerClient.SummarizeContributionsWithResponse(h.ctx)
	if err != nil || idleResp.JSON200 == nil || idleResp.JSON200.Status != sdk.Idle || idleResp.JSON200.DeclaredBytes != 0 {
		t.Fatalf("unexpected empty summary: %+v %v", idleResp.JSON200, err)
	}

	// Platform instance and custody-only unconsented contributor instance must NOT inflate contributor summary.
	h.instance(t, "platform-node", "platform-owner", "platform", 8192)
	custodyOnly := h.instance(t, "custody-unconsented", "student-0", "contributor", 0)
	custodyOnly.State = "paused"
	if _, err := svc.UpdateInstance(h.ctx, h.actor, "pause-c0", custodyOnly); err != nil {
		t.Fatal(err)
	}

	// A legacy unbound contributor can still hold bytes. Its usage must
	// not be counted as consented community capacity.
	if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		i, e := tx.Instance(custodyOnly.ID)
		if e != nil {
			return e
		}
		i.Used = 19
		i.Reserved = 3
		return tx.SaveInstance(i)
	}); err != nil {
		t.Fatal(err)
	}
	unbound, err := svc.SummarizeContributions(h.ctx, viewer)
	if err != nil || unbound.UsedBytes != 0 || unbound.ReservedBytes != 0 || unbound.RegisteredInstances != 0 {
		t.Fatal(unbound, err)
	}

	// Register two consented contributor instances: c1 (active, 2048 B) and c2 (paused, 1024 B).
	c1 := h.instance(t, "summary", "owner-secret-1", "contributor", 0)
	c1.State = "paused"
	c1, err = svc.UpdateInstance(h.ctx, h.actor, "prep-c1", c1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyContribution(h.ctx, h.actor, c1.ID, storage.ContributionControl{
		ID:               "ctrl-1",
		OwnerDomain:      "owner-secret-1",
		Revision:         1,
		ExpectedRevision: c1.Revision,
		State:            "active",
		LimitBytes:       2048,
		Until:            h.clock.Now().Add(2 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	operatorClient, err := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer operator")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := operatorClient.InspectContributionInstanceWithResponse(h.ctx, "summary", &sdk.InspectContributionInstanceParams{OwnerDomain: c1.OwnerDomain})
	if err != nil || instance.JSON200 == nil || instance.JSON200.InstanceId != "summary" {
		t.Fatal(instance, err)
	}

	// Upload 10 bytes onto c1 (pause platform-node first so c1 receives the replica).
	if _, err := svc.CommandInstance(h.ctx, h.actor, "platform-node", "pause-plat", storage.InstanceCommand{Revision: 1, Action: "pause"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("0123456789")
	obj := h.object(t, "contrib-file", payload)
	if _, err := svc.Ingest(h.ctx, h.actor, obj.ID, "up-contrib", bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}

	// Healthy state when all registered contributor instances are active with available bytes.
	beforeProbes := h.provider.verifyCalls
	healthyResp, err := viewerClient.SummarizeContributionsWithResponse(h.ctx)
	if err != nil || healthyResp.JSON200 == nil {
		t.Fatal(err)
	}
	s1 := healthyResp.JSON200
	if s1.Status != sdk.Healthy || s1.RegisteredInstances != 1 || s1.ActiveInstances != 1 || s1.DeclaredBytes != 2048 || s1.UsedBytes != 10 || s1.AvailableBytes != 2038 {
		t.Fatalf("unexpected healthy summary: %+v", s1)
	}
	if h.provider.verifyCalls != beforeProbes {
		t.Fatal("summary probed supplier")
	}

	// Add second contributor instance in paused state -> DeclaredBytes = 2048+1024 = 3072, AvailableBytes stays 2038, Status = degraded.
	c2 := h.instance(t, "contrib-secret-2", "owner-secret-2", "contributor", 0)
	c2.State = "paused"
	c2, err = svc.UpdateInstance(h.ctx, h.actor, "prep-c2", c2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyContribution(h.ctx, h.actor, c2.ID, storage.ContributionControl{
		ID:               "ctrl-2",
		OwnerDomain:      "owner-secret-2",
		Revision:         1,
		ExpectedRevision: c2.Revision,
		State:            "paused",
		LimitBytes:       1024,
		Until:            h.clock.Now().Add(2 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	degResp, err := viewerClient.SummarizeContributionsWithResponse(h.ctx)
	if err != nil || degResp.JSON200 == nil {
		t.Fatal(err)
	}
	s2 := degResp.JSON200
	if s2.Status != sdk.Degraded || s2.RegisteredInstances != 2 || s2.ActiveInstances != 1 || s2.DeclaredBytes != 3072 || s2.AvailableBytes != 2038 || s2.UsedBytes != 10 {
		t.Fatalf("unexpected degraded summary: %+v", s2)
	}
	rawJSON, _ := json.Marshal(s2)
	for _, secret := range []string{"contrib-secret", "owner-secret", "account:", "isolated"} {
		if strings.Contains(string(rawJSON), secret) {
			t.Fatalf("summary leaked instance identifier %q: %s", secret, rawJSON)
		}
	}

	// Advance clock past 5m QuotaValidity -> stale quota sample excluded from AvailableBytes & ActiveInstances -> Status = unavailable.
	h.clock.Add(6 * time.Minute)
	staleResp, err := viewerClient.SummarizeContributionsWithResponse(h.ctx)
	if err != nil || staleResp.JSON200 == nil {
		t.Fatal(err)
	}
	s3 := staleResp.JSON200
	if s3.Status != sdk.Unavailable || s3.ActiveInstances != 0 || s3.AvailableBytes != 0 || s3.DeclaredBytes != 3072 || s3.UsedBytes != 10 {
		t.Fatalf("stale quota sample was counted as available: %+v", s3)
	}
}

func TestContributionSummaryRejectsUnrepresentableCapacity(t *testing.T) {
	h := harnessFor(t)
	for n := 0; n < 8; n++ {
		id := fmt.Sprintf("large-%d", n)
		i := h.instance(t, id, id, "contributor", 0)
		i.State = "paused"
		i, err := h.s.UpdateInstance(h.ctx, h.actor, "pause-"+id, i)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.s.ApplyContribution(h.ctx, h.actor, id, storage.ContributionControl{ID: id, OwnerDomain: id, Revision: 1, ExpectedRevision: i.Revision, State: "active", LimitBytes: 1 << 60, Until: h.clock.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := h.s.SummarizeContributions(h.ctx, h.actor)
	if !errors.Is(err, storage.ErrUnavailable) || summary != (storage.ContributionSummary{}) {
		t.Fatal(summary, err)
	}
}
