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

func TestMissingReplicaIsRebuiltWithNewIntentAndBalancedCapacity(t *testing.T) {
	h := harnessFor(t, func(c *storage.Config) { c.VerificationAge = time.Minute })
	for n := 1; n <= 3; n++ {
		h.instance(t, fmt.Sprintf("i%d", n), "platform", "platform", 1024)
	}
	data := []byte("durable repair")
	o := h.object(t, "create", data)
	h.ingest(t, o.ID, data)
	h.reconcile(t)
	h.run(t)
	h.run(t)
	var previous storage.Replica
	if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		rs, e := tx.Replicas(o.ID)
		if e == nil {
			previous = rs[0]
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	h.provider.mu.Lock()
	delete(h.provider.files[previous.InstanceID], previous.Intent)
	h.provider.mu.Unlock()
	h.clock.Add(31 * time.Second)
	// Keep capacity evidence current without issuing writes or changing policy.
	for n := 1; n <= 3; n++ {
		if err := h.s.RefreshInstance(h.ctx, h.actor, fmt.Sprintf("i%d", n)); err != nil {
			t.Fatal(err)
		}
	}
	h.reconcile(t)
	lostSeen := false
	for n := 0; n < 20; n++ {
		_, err := h.s.RunOne(h.ctx, "repair-worker")
		if err != nil && !errors.Is(err, storage.ErrNotFound) && !errors.Is(err, storage.ErrStale) {
			t.Fatal(err)
		}
		if errors.Is(err, storage.ErrNotFound) {
			lostSeen = true
		}
		h.reconcile(t)
		st, err := h.s.Status(h.ctx, h.actor, o.ID)
		if err != nil {
			t.Fatal(err)
		}
		if st.Healthy < 3 {
			lostSeen = true
		}
		if st.Healthy == 3 && lostSeen {
			if err = h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
				rs, e := tx.Replicas(o.ID)
				if e != nil {
					return e
				}
				for _, r := range rs {
					if r.InstanceID == previous.InstanceID && (r.Intent == previous.Intent || r.Remote == previous.Remote || r.State != "healthy") {
						return errors.New("missing copy was not rebuilt")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
			for _, i := range instances {
				if i.Used != int64(len(data)) || i.Reserved != 0 {
					t.Fatal("repair capacity leak")
				}
			}
			var dst bytes.Buffer
			if err = h.s.Download(h.ctx, h.actor, o.ID, &dst); err != nil || !bytes.Equal(data, dst.Bytes()) {
				t.Fatal("repaired object cannot be delivered")
			}
			return
		}
	}
	t.Fatal("missing replica did not recover")
}

func TestOperationsAuthorizationCapacityFailuresAndPagination(t *testing.T) {
	h := harnessFor(t)
	for n := 1; n <= 3; n++ {
		h.instance(t, fmt.Sprintf("i%d", n), "platform", "platform", 1024)
	}
	o := h.object(t, "create", []byte("ops"))
	h.ingest(t, o.ID, []byte("ops"))
	h.reconcile(t)
	h.run(t)
	h.run(t)
	h.object(t, "second", []byte("pending"))
	instances, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	i := instances[2]
	i.Authorized = false
	i.State = "revoked"
	if _, err := h.s.UpdateInstance(h.ctx, h.actor, "revoke", i); err != nil {
		t.Fatal(err)
	}
	if err := h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		return tx.SaveJob(storage.Job{ID: "failed-job", ObjectID: o.ID, Kind: "replicate", State: "blocked", Attempts: 3, ErrorCode: storage.ErrUnavailable.Error(), AvailableAt: time.Now(), LeaseUntil: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	out, err := h.s.Operations(h.ctx, h.actor, 1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if out.Jobs.Blocked != 1 || len(out.Failures) != 1 || out.FailuresNextCursor != "failed-job" || out.NextCursor == "" || len(out.Objects) != 1 {
		t.Fatal("missing counts or cursors")
	}
	all, err := h.s.Operations(h.ctx, h.actor, 100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, obj := range all.Objects {
		if obj.ID == o.ID {
			found = true
			if obj.Healthy != 2 || obj.Missing != 1 || obj.Reason != "insufficient_eligible_capacity" {
				t.Fatalf("incorrect shortage: %+v", obj)
			}
		}
	}
	if !found {
		t.Fatal("missing object")
	}
	if all.Instances[2].Reason != "authorization_revoked" || all.Instances[2].AvailableBytes != 0 {
		t.Fatal("revoked instance capacity exposed as writable")
	}
	b, _ := json.Marshal(out)
	for _, secret := range []string{"credential_ref", "account_domain", "isolated", "sha256"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("operator snapshot leaked unnecessary data")
		}
	}
	h.auth.denied.Store(true)
	if _, err = h.s.Operations(h.ctx, h.actor, 10, "", ""); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("operations bypassed authorization")
	}
	h.auth.denied.Store(false)
	handler, err := httpapi.New(h.s, operatorAuth{}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := sdk.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.StorageOperationsWithResponse(context.Background(), nil)
	if err != nil || response.JSON200 == nil || response.JSON200.Jobs.Blocked != 1 {
		t.Fatal("operator SDK contract failed")
	}
	h.auth.denied.Store(true)
	response, err = client.StorageOperationsWithResponse(context.Background(), nil)
	if err != nil || response.StatusCode() != http.StatusForbidden {
		t.Fatal("operator HTTP authorization bypass")
	}
}

type operatorAuth struct{}

func (operatorAuth) Authenticate(*http.Request) (storage.Principal, error) {
	return storage.Principal{Issuer: "test", Subject: "operator"}, nil
}
