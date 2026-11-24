package storage

import (
	"context"
	"errors"
	"slices"
	"strings"
)

const admissionPolicyObject = "contribution-admission-policy"

type ContributionAdmissionRule struct {
	SubjectKind string   `json:"subject_kind"`
	SubjectID   string   `json:"subject_id"`
	InstanceID  string   `json:"instance_id,omitempty"`
	Levels      []string `json:"levels"`
}

type ContributionAdmissionMembership struct {
	OwnerDomain string   `json:"owner_domain"`
	RoleIDs     []string `json:"role_ids"`
	GroupIDs    []string `json:"group_ids"`
}

type ContributionAdmissionPolicy struct {
	Revision    int64                             `json:"revision"`
	Rules       []ContributionAdmissionRule       `json:"rules"`
	Memberships []ContributionAdmissionMembership `json:"memberships"`
}

func validOwnerDomain(v string) bool {
	return strings.HasPrefix(v, "owner:") && digest.MatchString(strings.TrimPrefix(v, "owner:"))
}

func validIDList(values []string, limit int) bool {
	if values == nil || len(values) > limit {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !validID(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func (p ContributionAdmissionPolicy) valid() bool {
	if p.Revision < 0 || p.Revision >= (1<<53)-1 || p.Rules == nil || p.Memberships == nil || len(p.Rules) > 100 || len(p.Memberships) > 100 {
		return false
	}
	keys := map[[3]string]bool{}
	for _, rule := range p.Rules {
		key := [3]string{rule.SubjectKind, rule.SubjectID, rule.InstanceID}
		if keys[key] || !validID(rule.SubjectID) || (rule.InstanceID != "" && !validID(rule.InstanceID)) || !validIDList(rule.Levels, 32) {
			return false
		}
		for _, level := range rule.Levels {
			if !validClass(level) {
				return false
			}
		}
		switch rule.SubjectKind {
		case "contributor":
			if !validOwnerDomain(rule.SubjectID) {
				return false
			}
		case "role", "group":
		default:
			return false
		}
		keys[key] = true
	}
	owners := map[string]bool{}
	for _, member := range p.Memberships {
		if !validOwnerDomain(member.OwnerDomain) || owners[member.OwnerDomain] || !validIDList(member.RoleIDs, 20) || !validIDList(member.GroupIDs, 20) {
			return false
		}
		owners[member.OwnerDomain] = true
	}
	return true
}

func (p ContributionAdmissionPolicy) levels(i Instance) []string {
	var member ContributionAdmissionMembership
	for _, current := range p.Memberships {
		if current.OwnerDomain == i.OwnerDomain {
			member = current
			break
		}
	}
	priority := 0
	allowed := []string{"public"}
	if i.Trusted && i.TrustConsent != nil {
		allowed = append(allowed, i.TrustConsent.Classes...)
	}
	for _, rule := range p.Rules {
		if rule.InstanceID != "" && rule.InstanceID != i.ID {
			continue
		}
		rank := 1
		if rule.InstanceID != "" {
			rank += 2
		}
		switch rule.SubjectKind {
		case "contributor":
			if rule.SubjectID != i.OwnerDomain {
				continue
			}
			rank++
		case "role":
			if !slices.Contains(member.RoleIDs, rule.SubjectID) {
				continue
			}
		case "group":
			if !slices.Contains(member.GroupIDs, rule.SubjectID) {
				continue
			}
		}
		switch {
		case rank > priority:
			priority = rank
			allowed = slices.Clone(rule.Levels)
		case rank == priority:
			allowed = slices.DeleteFunc(allowed, func(level string) bool { return !slices.Contains(rule.Levels, level) })
		}
	}
	slices.Sort(allowed)
	return allowed
}

func readAdmissionPolicy(tx Transaction) (ContributionAdmissionPolicy, error) {
	value, err := tx.ContributionAdmissionPolicy()
	if errors.Is(err, ErrNotFound) {
		return ContributionAdmissionPolicy{
			Rules: []ContributionAdmissionRule{}, Memberships: []ContributionAdmissionMembership{},
		}, nil
	}
	return value, err
}

func (s *Service) ContributionAdmissionPolicy(ctx context.Context, p Principal) (ContributionAdmissionPolicy, error) {
	if err := s.authorize(ctx, p, "storage.admissions.read", admissionPolicyObject, Protection{}); err != nil {
		return ContributionAdmissionPolicy{}, err
	}
	var result ContributionAdmissionPolicy
	err := s.readTx(ctx, func(tx Transaction) error {
		var err error
		result, err = readAdmissionPolicy(tx)
		return err
	})
	return result, err
}

func (s *Service) ReplaceContributionAdmissionPolicy(ctx context.Context, p Principal, key string, policy ContributionAdmissionPolicy) (ContributionAdmissionPolicy, error) {
	var result ContributionAdmissionPolicy
	guard := func(Transaction) error {
		return s.authorize(ctx, p, "storage.admissions.manage", admissionPolicyObject, Protection{})
	}
	err := s.mutation(ctx, p, "storage.admissions.manage", admissionPolicyObject, key, policy, guard, func(tx Transaction) (any, error) {
		if !policy.valid() {
			return nil, ErrInput
		}
		if err := tx.Lock("instance-registry"); err != nil {
			return nil, err
		}
		previous, err := readAdmissionPolicy(tx)
		if err != nil {
			return nil, err
		}
		if policy.Revision != previous.Revision {
			return nil, ErrConflict
		}
		if err := s.applyContributionAdmissionLevels(ctx, tx, p, policy); err != nil {
			return nil, err
		}
		policy.Revision++
		if err := tx.SaveContributionAdmissionPolicy(policy); err != nil {
			return nil, err
		}
		return policy, s.emit(ctx, tx, p, "storage.contribution_admission.updated", admissionPolicyObject, policy.Revision)
	}, &result)
	return result, err
}

func (s *Service) applyContributionAdmissionLevels(ctx context.Context, tx Transaction, actor Principal, policy ContributionAdmissionPolicy) error {
	instances, err := tx.Instances(100, "")
	if err != nil {
		return err
	}
	for _, snapshot := range instances {
		if snapshot.Ownership != "contributor" {
			continue
		}
		i, err := tx.Instance(snapshot.ID)
		if err != nil {
			return err
		}
		levels := policy.levels(i)
		if slices.Equal(levels, i.effectiveContributionLevels()) {
			continue
		}
		i.ContributionLevels = &levels
		if err := tx.SaveInstance(i); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, actor, "storage.instance.admissions_changed", i.ID, policy.Revision+1); err != nil {
			return err
		}
	}
	return nil
}
