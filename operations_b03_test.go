package storage_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/auditquery"
	"github.com/StuHelper/stuhelper-storage/httpapi"
	"github.com/StuHelper/stuhelper-storage/sdk"
)

type reviewOnlyAuthorizer struct {
	base   storage.Authorizer
	review storage.Principal
}

func (a reviewOnlyAuthorizer) Authorize(ctx context.Context, p storage.Principal, action, id string, protection storage.Protection) error {
	if p == a.review {
		if action == "storage.objects.review" {
			return nil
		}
		return storage.ErrDenied
	}
	return a.base.Authorize(ctx, p, action, id, protection)
}

type headerPrincipalAuth struct{}

func (headerPrincipalAuth) Authenticate(r *http.Request) (storage.Principal, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer operator":
		return storage.Principal{Issuer: "test-issuer", Subject: "operator"}, nil
	case "Bearer reviewer":
		return storage.Principal{Issuer: "test-issuer", Subject: "reviewer"}, nil
	default:
		return storage.Principal{}, storage.ErrDenied
	}
}

func TestOperationsFilteringTotalsReviewRouteAndUnknownWriteOff(t *testing.T) {
	h := harnessFor(t, func(c *storage.Config) { c.MaxAttempts = 1 })
	reviewer := storage.Principal{Issuer: "test-issuer", Subject: "reviewer"}
	customAuth := reviewOnlyAuthorizer{base: h.auth, review: reviewer}
	svc, err := storage.New(h.repo, customAuth, h.provider, h.provider, storage.Config{
		Clock:              h.clock.Now,
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: t.TempDir(),
		ParallelTransfers:  4,
		Lease:              time.Minute,
		VerificationAge:    time.Hour,
		MaxAttempts:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	for n := 1; n <= 3; n++ {
		_, err := svc.Register(h.ctx, h.actor, fmt.Sprintf("reg-%d", n), storage.Instance{
			ID:                 fmt.Sprintf("i%d", n),
			Adapter:            "test",
			AccountDomain:      "alias",
			OwnerDomain:        fmt.Sprintf("owner-%d", n),
			Ownership:          "platform",
			CredentialRef:      fmt.Sprintf("i%d", n),
			CredentialRevision: 1,
			Root:               "isolated",
			State:              "active",
			Authorized:         true,
			Limit:              4096,
			ExpiresAt:          h.clock.Now().Add(24 * time.Hour),
			Admissions:         []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: h.clock.Now().Add(24 * time.Hour)}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Ready object (3/3 replicas).
	readyData := []byte("ready-three-copies")
	readyObj := h.object(t, "obj-ready", readyData)
	if _, err := svc.Ingest(h.ctx, h.actor, readyObj.ID, "up-ready", bytes.NewReader(readyData)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reconcile(h.ctx, h.actor, 100, ""); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if worked, err := svc.RunOne(h.ctx, "worker"); err != nil || !worked {
			t.Fatal(worked, err)
		}
	}

	// Degraded object (2/3 replicas: pause i3 before reconciling).
	if _, err := svc.CommandInstance(h.ctx, h.actor, "i3", "pause-i3", storage.InstanceCommand{Revision: 1, Action: "pause"}); err != nil {
		t.Fatal(err)
	}
	degData := []byte("degraded-two-copies")
	degObj := h.object(t, "obj-degraded", degData)
	if _, err := svc.Ingest(h.ctx, h.actor, degObj.ID, "up-deg", bytes.NewReader(degData)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reconcile(h.ctx, h.actor, 100, ""); err != nil {
		t.Fatal(err)
	}
	for {
		worked, err := svc.RunOne(h.ctx, "worker")
		if err != nil {
			t.Fatal(err)
		}
		if !worked {
			break
		}
	}

	// Unpublished 1-replica object for review download (pause i2 so only i1 is writable).
	if _, err := svc.CommandInstance(h.ctx, h.actor, "i2", "pause-i2", storage.InstanceCommand{Revision: 1, Action: "pause"}); err != nil {
		t.Fatal(err)
	}
	reviewData := []byte("single-copy-awaiting-moderation")
	reviewObj := h.object(t, "obj-review", reviewData)
	if _, err := svc.Ingest(h.ctx, h.actor, reviewObj.ID, "up-review", bytes.NewReader(reviewData)); err != nil {
		t.Fatal(err)
	}

	// Deleted empty object (should be excluded from active ObjectTotals).
	delObj := h.object(t, "obj-deleted", []byte("gone"))
	if _, err := svc.Delete(h.ctx, h.actor, delObj.ID, "del-empty", delObj.Revision); err != nil {
		t.Fatal(err)
	}

	// Unknown-begin object producing blocked ingest job with IssuedWrite=true && Remote.ID=="".
	unkData := []byte("ambiguous-begin-payload")
	unkObj := h.object(t, "obj-unknown", unkData)
	h.provider.lostBegin = true
	if _, err := svc.Ingest(h.ctx, h.actor, unkObj.ID, "up-unk", bytes.NewReader(unkData)); !errors.Is(err, storage.ErrUnknown) {
		t.Fatalf("expected ErrUnknown, got %v", err)
	}
	h.provider.lostBegin = false

	handler, err := httpapi.New(svc, headerPrincipalAuth{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	opClient, err := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer operator")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Verify ObjectTotals and problematic object filter + failure filters via SDK.
	probFilter := sdk.StorageOperationsParamsObjectFilter("problematic")
	blockedState := sdk.StorageOperationsParamsFailureState("blocked")
	ingestKind := sdk.StorageOperationsParamsFailureKind("ingest")
	errCode := storage.ErrUnknown.Error()
	opsResp, err := opClient.StorageOperationsWithResponse(h.ctx, &sdk.StorageOperationsParams{
		ObjectFilter: &probFilter,
		FailureState: &blockedState,
		FailureKind:  &ingestKind,
		ErrorCode:    &errCode,
	})
	if err != nil || opsResp.JSON200 == nil {
		t.Fatalf("operations query failed: %v", err)
	}
	totals := opsResp.JSON200.ObjectTotals
	if totals.Ready != 1 || totals.Degraded != 1 || totals.Pending != 2 || totals.Unavailable != 0 || totals.Deleting != 0 {
		t.Fatalf("unexpected object_totals: %+v", totals)
	}
	if len(opsResp.JSON200.Objects) != 1 || opsResp.JSON200.Objects[0].Id != degObj.ID {
		t.Fatalf("expected only degraded object in problematic filter, got %+v", opsResp.JSON200.Objects)
	}
	if len(opsResp.JSON200.Failures) != 1 || opsResp.JSON200.Failures[0].ObjectId != unkObj.ID || opsResp.JSON200.Failures[0].ReplicaId == nil || *opsResp.JSON200.Failures[0].ReplicaId == "" {
		t.Fatalf("expected filtered unknown-begin failure with replica_id, got %+v", opsResp.JSON200.Failures)
	}
	otherCode := storage.ErrIntegrity.Error()
	emptyFailResp, err := opClient.StorageOperationsWithResponse(h.ctx, &sdk.StorageOperationsParams{ErrorCode: &otherCode})
	if err != nil || emptyFailResp.JSON200 == nil || len(emptyFailResp.JSON200.Failures) != 0 {
		t.Fatalf("expected 0 failures for non-matching error_code, got %+v %v", emptyFailResp, err)
	}

	// 2. Verify HTTP review-content route works with review-only permission (without read/download) and records audit.
	revClient, err := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer reviewer")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	normalDownload, err := revClient.DownloadContentWithResponse(h.ctx, reviewObj.ID)
	if err != nil || normalDownload.StatusCode() != http.StatusForbidden {
		t.Fatalf("reviewer without download grant must be denied ordinary download, got %d", normalDownload.StatusCode())
	}
	reviewResp, err := revClient.ReviewObjectContentWithResponse(h.ctx, reviewObj.ID)
	if err != nil || reviewResp.StatusCode() != http.StatusOK || !bytes.Equal(reviewResp.Body, reviewData) {
		t.Fatalf("review HTTP download failed: status=%d err=%v", reviewResp.StatusCode(), err)
	}

	// 3. Verify WriteOffUnknownReplica validation, fencing, reservation release, and audit reason persistence.
	replicaID := *opsResp.JSON200.Failures[0].ReplicaId
	var i1Rev int64
	for _, inst := range opsResp.JSON200.Instances {
		if inst.Id == "i1" {
			i1Rev = inst.Revision
			if inst.ReservedBytes != int64(len(unkData)) {
				t.Fatalf("expected frozen reservation %d on i1, got %d", len(unkData), inst.ReservedBytes)
			}
		}
	}
	// Reject control character in reason.
	badReason, err := opClient.WriteOffUnknownReplicaWithResponse(h.ctx, unkObj.ID, replicaID, &sdk.WriteOffUnknownReplicaParams{IdempotencyKey: "bad-reason"}, sdk.ReplicaWriteOff{
		ObjectRevision:   unkObj.Revision,
		InstanceRevision: i1Rev,
		Reason:           "bad\ncontrol",
	})
	if err != nil || badReason.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected 400 for control-char reason, got %d", badReason.StatusCode())
	}
	// Reject write-off on healthy known-locator replica.
	var readyReplicaID string
	if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		rs, e := tx.Replicas(readyObj.ID)
		if e == nil && len(rs) > 0 {
			readyReplicaID = rs[0].ID
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	knownReject, err := opClient.WriteOffUnknownReplicaWithResponse(h.ctx, readyObj.ID, readyReplicaID, &sdk.WriteOffUnknownReplicaParams{IdempotencyKey: "known-reject"}, sdk.ReplicaWriteOff{
		ObjectRevision:   readyObj.Revision,
		InstanceRevision: i1Rev,
		Reason:           "verified isolated root has file",
	})
	if err != nil || knownReject.StatusCode() != http.StatusConflict {
		t.Fatalf("expected 409 for known-remote replica writeoff, got %d", knownReject.StatusCode())
	}

	// Valid operator write-off releases reserved bytes and clears blocked job.
	reasonText := "checked isolated root stuhelper-storage; no file created"
	woResp, err := opClient.WriteOffUnknownReplicaWithResponse(h.ctx, unkObj.ID, replicaID, &sdk.WriteOffUnknownReplicaParams{IdempotencyKey: "wo-1"}, sdk.ReplicaWriteOff{
		ObjectRevision:   unkObj.Revision,
		InstanceRevision: i1Rev,
		Reason:           reasonText,
	})
	if err != nil || woResp.JSON200 == nil {
		t.Fatalf("write-off failed: status=%d err=%v body=%s", woResp.StatusCode(), err, string(woResp.Body))
	}
	if woResp.JSON200.Instance.ReservedBytes != 0 {
		t.Fatalf("expected 0 reserved bytes after write-off, got %d", woResp.JSON200.Instance.ReservedBytes)
	}
	// Idempotent replay returns identical response.
	woReplay, err := opClient.WriteOffUnknownReplicaWithResponse(h.ctx, unkObj.ID, replicaID, &sdk.WriteOffUnknownReplicaParams{IdempotencyKey: "wo-1"}, sdk.ReplicaWriteOff{
		ObjectRevision:   unkObj.Revision,
		InstanceRevision: i1Rev,
		Reason:           reasonText,
	})
	if err != nil || woReplay.StatusCode() != http.StatusOK || woReplay.JSON200.Instance.Revision != woResp.JSON200.Instance.Revision {
		t.Fatalf("write-off replay failed: %+v %v", woReplay, err)
	}

	afterOps, err := opClient.StorageOperationsWithResponse(h.ctx, nil)
	if err != nil || afterOps.JSON200 == nil || afterOps.JSON200.Jobs.Blocked != 0 || len(afterOps.JSON200.Failures) != 0 {
		t.Fatalf("expected blocked job cleared after write-off, got %+v", afterOps.JSON200)
	}

	// Verify both review audit and write-off audit reason via public ReadAudit reader.
	batch, err := h.repo.ReadAudit(h.ctx, auditquery.Request{
		Scopes: []auditquery.Scope{{School: "*", Group: "*", Module: "storage"}},
		Until:  h.clock.Now().Add(time.Hour),
		Limit:  50,
	})
	if err != nil {
		t.Fatal(err)
	}
	sawReviewAudit, sawWriteOffReason := false, false
	for _, rec := range batch.Records {
		if rec.Action == "storage.object.reviewed.v1" && rec.Target == reviewObj.ID && strings.Contains(rec.Actor, "cmV2aWV3ZXI") {
			sawReviewAudit = true
		}
		if rec.Action == "storage.replica.writeoff.v1" && rec.Target == unkObj.ID && rec.Reason == reasonText {
			sawWriteOffReason = true
		}
	}
	if !sawReviewAudit || !sawWriteOffReason {
		t.Fatalf("missing audit records: review=%v writeoff=%v records=%+v", sawReviewAudit, sawWriteOffReason, batch.Records)
	}
}
