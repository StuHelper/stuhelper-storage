package storage_test

import (
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"testing"
	"time"
)

func TestContributionControlFencesOwnershipReplayAndConsentExpiry(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "contributor", "owner", "contributor", 1024)
	i.State = "paused"
	var err error
	i, err = h.s.UpdateInstance(h.ctx, h.actor, "prepare", i)
	if err != nil {
		t.Fatal(err)
	}
	control := storage.ContributionControl{ID: "consent", OwnerDomain: "owner", Revision: 1, ExpectedRevision: i.Revision, State: "active", LimitBytes: 1024, PersonalReserve: 100, Until: h.clock.Now().Add(time.Hour)}
	if _, err = h.s.InspectContribution(h.ctx, h.actor, i.ID, "other"); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("foreign ownership", err)
	}
	first, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, control)
	if err != nil || first.Control == nil || first.AvailableBytes != 1024 {
		t.Fatal(first, err)
	}
	control.ExpectedRevision = first.Revision
	replay, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, control)
	if err != nil || replay.Revision != first.Revision {
		t.Fatal("replay changed revision", err)
	}
	control.LimitBytes = 2048
	if _, err = h.s.ApplyContribution(h.ctx, h.actor, i.ID, control); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("same revision changed consent", err)
	}
	control.LimitBytes = 1024
	control.Revision = 2
	control.State = "paused"
	paused, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, control)
	if err != nil {
		t.Fatal(err)
	}
	old := control
	old.Revision = 1
	old.State = "active"
	if _, err = h.s.ApplyContribution(h.ctx, h.actor, i.ID, old); !errors.Is(err, storage.ErrStale) {
		t.Fatal("late activation", err)
	}
	control.Revision = 3
	control.ExpectedRevision = paused.Revision
	control.State = "active"
	if _, err = h.s.ApplyContribution(h.ctx, h.actor, i.ID, control); err != nil {
		t.Fatal(err)
	}
	itemsBefore, err := h.s.Instances(h.ctx, h.actor, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	admin := itemsBefore[0]
	admin.Limit = 1 << 20
	admin.PersonalReserve = 0
	admin.ContributionControl = nil
	admin, err = h.s.UpdateInstance(h.ctx, h.actor, "generic-update", admin)
	if err != nil || admin.Limit != 1024 || admin.PersonalReserve != 100 || admin.ContributionControl == nil {
		t.Fatal("generic update changed consent", admin, err)
	}
	tooLarge := int64(2048)
	if _, err = h.s.CommandInstance(h.ctx, h.actor, i.ID, "excess-quota", storage.InstanceCommand{Action: "quota", Revision: admin.Revision, LimitBytes: &tooLarge}); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("operator quota exceeded user consent", err)
	}
	h.clock.Add(time.Hour + time.Second)
	items, err := h.s.Instances(h.ctx, h.actor, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if items[0].CanWrite(storage.Protection{Class: "public", Scope: "school-a", Public: true}, 1, h.clock.Now()) || !items[0].Draining(h.clock.Now()) {
		t.Fatal("expired consent still writable")
	}
	snapshot, err := h.s.InspectContribution(h.ctx, h.actor, i.ID, "owner")
	if err != nil || snapshot.AvailableBytes != 0 {
		t.Fatal(snapshot, err)
	}
	h.auth.denied.Store(true)
	if _, err = h.s.ApplyContribution(h.ctx, h.actor, i.ID, control); !errors.Is(err, storage.ErrDenied) {
		t.Fatal("replay ignored permission", err)
	}
}

func TestContributionExitWaitsForRecordedReplicaCleanup(t *testing.T) {
	h := harnessFor(t)
	i := h.instance(t, "contributor", "owner", "contributor", 1024)
	i.State = "paused"
	var err error
	i, err = h.s.UpdateInstance(h.ctx, h.actor, "prepare", i)
	if err != nil {
		t.Fatal(err)
	}
	c := storage.ContributionControl{ID: "consent", OwnerDomain: "owner", Revision: 1, ExpectedRevision: i.Revision, State: "active", LimitBytes: 1024, Until: h.clock.Now().Add(time.Hour)}
	bound, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, c)
	if err != nil {
		t.Fatal(err)
	}
	o := h.object(t, "file", []byte("x"))
	h.ingest(t, o.ID, []byte("x"))
	c.Revision++
	c.ExpectedRevision = bound.Revision
	c.State = "draining"
	c.LimitBytes = 0 // A stop request must not be blocked by concurrent occupancy.
	drain, err := h.s.ApplyContribution(h.ctx, h.actor, i.ID, c)
	if err != nil || drain.UsedBytes != 1 || drain.RemainingReplicas != 1 {
		t.Fatal("remaining object mistaken for complete exit", drain, err)
	}
	c.Revision++
	c.ExpectedRevision = drain.Revision
	c.State = "active"
	if _, err = h.s.ApplyContribution(h.ctx, h.actor, i.ID, c); !errors.Is(err, storage.ErrConflict) {
		t.Fatal("exit cancelled by resume", err)
	}
	if _, err = h.s.Delete(h.ctx, h.actor, o.ID, "delete", o.Revision); err != nil {
		t.Fatal(err)
	}
	h.run(t)
	drain, err = h.s.InspectContribution(h.ctx, h.actor, i.ID, "owner")
	if err != nil || drain.RemainingReplicas != 0 {
		t.Fatal("remaining objects", drain, err)
	}
}
