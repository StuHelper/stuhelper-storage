package storage_test

import (
	storage "github.com/StuHelper/stuhelper-storage"
	"testing"
)

func TestCoolingOwnerDrainsExistingAndNewInstancesAndCancelsOnlyOwnBarrier(t *testing.T) {
	h := harnessFor(t)
	owner := "owner:synthetic"
	const closure = "first-request"
	h.instance(t, "owned", owner, 1024)
	h.instance(t, "other", "other-owner", 1024)
	p := storage.Protection{Class: "public", Scope: "school-a", Public: true}
	checkState := func(id string, blocked bool) {
		t.Helper()
		list, err := h.s.Instances(h.ctx, h.actor, 100, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range list {
			if i.ID == id {
				if i.ClosureDraining != blocked || i.Draining(h.clock.Now()) != blocked || (blocked && i.CanWrite(p, 1, h.clock.Now())) {
					t.Fatalf("instance %s closure=%v", id, i.ClosureDraining)
				}
				return
			}
		}
		t.Fatalf("missing instance %s", id)
	}
	set := func(id string, cancel bool) {
		t.Helper()
		if err := h.s.SetOwnerClosure(h.ctx, h.actor, owner, id, cancel); err != nil {
			t.Fatal(err)
		}
	}
	set(closure, false)
	h.instance(t, "new", owner, 1024)
	checkState("new", true)
	checkState("owned", true)
	checkState("other", false)
	done, err := h.s.OwnerDrainComplete(h.ctx, h.actor, owner, closure)
	if err != nil || !done {
		t.Fatal(done, err)
	}
	set(closure, true)
	checkState("owned", false)
	set("next-request", false)
	set(closure, true)
	set(closure, false)
	checkState("owned", true)
	done, err = h.s.OwnerDrainComplete(h.ctx, h.actor, owner, closure)
	if err != nil || done {
		t.Fatal("stale closure accepted", done, err)
	}
}

func TestClosureDrainsToVerifiedFallbackAndRepairsWhenContributionReturns(t *testing.T) {
	h := harnessFor(t)
	source := registerContributor(t, h, "departing", h.actor, 4096)
	payload := []byte("synthetic test content")
	obj := h.object(t, "object", payload)
	h.ingest(t, obj.ID, payload)
	if err := h.s.SetOwnerClosure(h.ctx, h.actor, source.OwnerDomain, "closing", false); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t)
	check := func(want bool) {
		t.Helper()
		done, err := h.s.OwnerDrainComplete(h.ctx, h.actor, source.OwnerDomain, "closing")
		if done != want || err != nil {
			t.Fatalf("drain=%v expected %v: %v", done, want, err)
		}
	}
	check(false)
	if err := h.s.ConfigureFallback(h.ctx, h.actor, storage.FallbackConfig{ID: "fallback", AccountDomain: "cos:fixture", Root: "replicas", Scopes: []string{"school-a"}, AlertPercent: 80, Limit: 4096}); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t)
	check(false)
	h.run(t)
	h.reconcile(t)
	h.run(t)
	check(true)
	state, err := h.s.Status(h.ctx, h.actor, obj.ID)
	if err != nil || !state.VerifiedCOSOnly || state.Healthy != 1 {
		t.Fatalf("verified fallback: %+v %v", state, err)
	}
	registerContributor(t, h, "replacement", storage.Principal{Issuer: "fixture", Subject: "replacement"}, 4096)
	h.reconcile(t)
	h.run(t)
	state, err = h.s.Status(h.ctx, h.actor, obj.ID)
	if err != nil || state.Healthy != 2 {
		t.Fatalf("restored contribution: %+v %v", state, err)
	}
}
