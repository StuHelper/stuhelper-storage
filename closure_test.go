package storage_test

import (
	storage "github.com/StuHelper/stuhelper-storage"
	"testing"
)

func TestCoolingOwnerDrainsExistingAndNewInstancesAndCancelsOnlyOwnBarrier(t *testing.T) {
	h := harnessFor(t)
	owner := "owner:synthetic"
	const closure = "first-request"
	h.instance(t, "owned", owner, "contributor", 1024)
	h.instance(t, "other", "other-owner", "contributor", 1024)
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
	h.instance(t, "new", owner, "contributor", 1024)
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
