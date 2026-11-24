package storage

import (
	"context"
	"maps"
	"slices"
	"time"
)

// reserveMinimum runs under the object's transaction. Ingest claims the first
// held replica; its verified completion schedules the remaining held copies.
func (s *Service) reserveMinimum(tx Transaction, o Object) error {
	if o.State == "deleting" || o.State == "deleted" {
		return ErrConflict
	}
	replicas, err := tx.Replicas(o.ID)
	if err != nil {
		return err
	}
	_, instances, err := lockCandidateInstances(tx, replicas)
	if err != nil {
		return err
	}
	seen := newIndependentSet()
	fallback := false
	now := s.now()
	for _, r := range replicas {
		i := instances[r.InstanceID]
		if healthyVerifiedReplica(r, o, i, now, s.cfg.VerificationAge) || reservationUsable(r, o, i, now) {
			seen.add(i)
			fallback = fallback || i.IsFallback()
		}
	}
	needed := o.Policy.Publish - len(seen)
	if needed <= 0 {
		return nil
	}
	planned, err := s.plan(tx, o, needed)
	if err != nil {
		return err
	}
	for _, r := range planned {
		i := instances[r.InstanceID]
		fallback = fallback || i.IsFallback()
		seen.add(i)
		r.State = "held"
		if err := tx.SaveReplica(r); err != nil {
			return err
		}
	}
	if len(seen) >= o.Policy.Publish {
		return nil
	}
	if len(seen) == 1 && fallback && o.Policy.Publish == 2 {
		for _, i := range instances {
			if !i.IsFallback() && i.CanWrite(o.Protection, o.storedBytes(), now) {
				return ErrCapacity
			}
		}
		return nil
	}
	candidates := make([]Instance, 0, len(instances))
	for _, i := range instances {
		candidates = append(candidates, i)
	}
	estimate, _ := describeStage(candidates, o.Protection, o.storedBytes(), now)
	if estimate.Reason == ErrReplicaSpace.Error() {
		return ErrReplicaSpace
	}
	return ErrReplicaShortage
}

func reservationUsable(r Replica, o Object, i Instance, now time.Time) bool {
	if r.State != "held" && r.State != "reserved" && r.State != "writing" {
		return false
	}
	if !r.Reserved || r.ObjectRevision != o.Revision || r.CredentialRevision != i.CredentialRevision ||
		r.InstanceRevision != i.Revision || r.Size != o.storedBytes() || i.Reserved < r.Size {
		return false
	}
	i.Reserved -= r.Size
	return i.CanWrite(o.Protection, o.storedBytes(), now)
}

func (s *Service) firstIngestReplica(tx Transaction, o Object) (Replica, bool, error) {
	replicas, err := tx.Replicas(o.ID)
	if err != nil {
		return Replica{}, false, err
	}
	// Ingest replay acknowledges already stored immutable bytes. Read and
	// publication decisions independently check the verification age.
	for _, r := range replicas {
		if r.State == "healthy" && r.ObjectRevision == o.Revision {
			return Replica{}, true, nil
		}
	}
	var first Replica
	fallback := true
	for _, r := range replicas {
		if r.State == "deleted" {
			continue
		}
		i, err := tx.Instance(r.InstanceID)
		if err != nil {
			return Replica{}, false, err
		}
		if r.State != "held" {
			return Replica{}, false, ErrConflict
		}
		if !reservationUsable(r, o, i, s.now()) {
			return Replica{}, false, ErrCapacity
		}
		if first.ID == "" || fallback && !i.IsFallback() {
			first = r
			fallback = i.IsFallback()
		}
	}
	if first.ID != "" {
		return first, false, nil
	}
	planned, err := s.plan(tx, o, 1)
	if err != nil {
		return Replica{}, false, err
	}
	if len(planned) == 0 {
		return Replica{}, false, ErrCapacity
	}
	return planned[0], false, nil
}

func (s *Service) scheduleHeld(tx Transaction, o Object) error {
	replicas, err := tx.Replicas(o.ID)
	if err != nil {
		return err
	}
	for _, r := range replicas {
		if r.State != "held" {
			continue
		}
		if err := s.enqueue(tx, o.ID, r.ID, "replicate"); err != nil {
			return err
		}
	}
	return nil
}

type Intake struct {
	Mode                 string `json:"mode"`
	Reason               string `json:"reason,omitempty"`
	ContributionAccounts int    `json:"contribution_accounts"`
}

type intakeError string

func (e intakeError) Error() string { return string(e) }
func (e intakeError) Unwrap() error { return ErrCapacity }

const ErrReplicaShortage intakeError = "storage_replica_shortage"
const ErrReplicaSpace intakeError = "storage_replica_space"

func describeStage(instances []Instance, p Protection, size int64, now time.Time) (Intake, []int) {
	ordinary := newIndependentSet()
	var picked []int
	fallback := -1
	potential := newIndependentSet()
	hasCOS := false
	for n, i := range instances {
		if !i.currentPlacementQuota(now) || !i.Allows(p, now) {
			continue
		}
		potential.add(i)
		hasCOS = hasCOS || i.IsFallback()
		if !i.CanWrite(p, size, now) {
			continue
		}
		if i.IsFallback() {
			fallback = n
			continue
		}
		if !ordinary.seen(i) {
			ordinary.add(i)
			if len(picked) < 2 {
				picked = append(picked, n)
			}
		}
	}
	out := Intake{Mode: "bhpan", ContributionAccounts: len(ordinary)}
	if len(picked) >= 2 {
		return out, picked
	}
	if fallback >= 0 {
		out.Mode = "mixed"
		if len(picked) == 0 {
			out.Mode = "cos_only"
		}
		return out, append(picked, fallback)
	}
	out.Mode = "paused"
	out.Reason = ErrReplicaShortage.Error()
	if len(potential) >= 2 || hasCOS {
		out.Reason = ErrReplicaSpace.Error()
	}
	return out, nil
}

// CheckPlacement estimates a new upload without claiming space. It models
// simultaneous source and destination allocations. Create performs the locked
// reservation and can also reuse matching verified physical content.
func (s *Service) CheckPlacement(ctx context.Context, p Principal, protections []Protection, size int64) (Intake, error) {
	if size < 1 || size > s.cfg.MaxObjectSize || len(protections) < 1 || len(protections) > 2 {
		return Intake{}, ErrInput
	}
	for _, protection := range protections {
		if !protection.Valid() {
			return Intake{}, ErrInput
		}
		if err := s.authorize(ctx, p, "storage.objects.create", "", protection); err != nil {
			return Intake{}, err
		}
	}
	var result Intake
	err := s.readTx(ctx, func(tx Transaction) error {
		candidates, err := tx.Instances(100, "")
		if err != nil {
			return err
		}
		for n, protection := range protections {
			if n > 0 && protection == protections[0] {
				continue
			}
			if protection.Class == "restricted" && s.cfg.ContentKeys == nil {
				result = Intake{Mode: "paused", Reason: ErrRestrictedUnavailable.Error()}
				break
			}
			physical := storedSize(protection, size)
			stage, selected := describeStage(candidates, protection, physical, s.now())
			if stage.Mode == "paused" {
				result = stage
				break
			}
			if n == 0 || result.ContributionAccounts > stage.ContributionAccounts {
				result = stage
			}
			for _, idx := range selected {
				candidates[idx].Reserved += physical
			}
		}
		return nil
	})
	return result, err
}

type SchoolIntake struct {
	Scope                string `json:"scope"`
	Class                string `json:"class"`
	Mode                 string `json:"mode"`
	ContributionAccounts int    `json:"contribution_accounts"`
	MaxFileBytes         int64  `json:"max_file_bytes"`
	Reason               string `json:"reason,omitempty"`
}

// The maximum physical file size is bounded by either a pair of independent
// contribution budgets or a COS budget. Multi-stage uploads check the joint peak.
func (s *Service) schoolIntake(instances []Instance, now time.Time) []SchoolIntake {
	scopes := map[string]bool{}
	for _, scope := range s.cfg.IntakeScopes {
		scopes[scope] = true
	}
	for _, i := range instances {
		for _, a := range i.Admissions {
			scopes[a.Scope] = true
		}
	}
	out := []SchoolIntake{}
	for _, scope := range slices.Sorted(maps.Keys(scopes)) {
		for _, class := range []string{"public", "quarantine", "restricted"} {
			p := Protection{Class: class, Scope: scope, Public: class == "public"}
			if class == "restricted" && s.cfg.ContentKeys == nil {
				out = append(out, SchoolIntake{Scope: scope, Class: class, Mode: "paused", Reason: ErrRestrictedUnavailable.Error()})
				continue
			}
			state, _ := describeStage(instances, p, storedSize(p, 1), now)
			var largest, second, cosBudget int64
			for _, i := range instances {
				if !i.CanWrite(p, storedSize(p, 1), now) {
					continue
				}
				budget := logicalBudget(p, i.writeBudget())
				if i.IsFallback() {
					cosBudget = budget
					continue
				}
				if budget >= largest {
					largest, second = budget, largest
				} else if budget > second {
					second = budget
				}
			}
			out = append(out, SchoolIntake{scope, class, state.Mode, state.ContributionAccounts, min(s.cfg.MaxObjectSize, max(second, cosBudget)), state.Reason})
		}
	}
	return out
}
