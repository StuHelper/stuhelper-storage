package storage

import (
	"slices"
	"testing"
)

func TestAdmissionPolicySelectorsAndDefault(t *testing.T) {
	owner := ContributionOwnerDomain(Principal{Issuer: "synthetic", Subject: "owner"})
	member := Instance{ID: "approved", OwnerDomain: owner}
	policy := ContributionAdmissionPolicy{
		Rules: []ContributionAdmissionRule{
			{SubjectKind: "role", SubjectID: "maintainer", Levels: []string{"public", "quarantine"}},
			{SubjectKind: "group", SubjectID: "public-only", Levels: []string{"public"}},
			{SubjectKind: "contributor", SubjectID: owner, InstanceID: "approved", Levels: []string{"quarantine"}},
		},
		Memberships: []ContributionAdmissionMembership{{OwnerDomain: owner, RoleIDs: []string{"maintainer"}, GroupIDs: []string{"public-only"}}},
	}
	if !policy.valid() {
		t.Fatal("valid policy rejected")
	}
	if got := policy.levels(member); !slices.Equal(got, []string{"quarantine"}) {
		t.Fatal("instance rule lost to global membership", got)
	}
	member.ID = "different-instance"
	if got := policy.levels(member); !slices.Equal(got, []string{"public"}) {
		t.Fatal("role and group did not intersect", got)
	}
	if got := policy.levels(Instance{ID: "approved", OwnerDomain: "other-owner"}); !slices.Equal(got, []string{"public"}) {
		t.Fatal("instance rule leaked to another contributor", got)
	}
	policy.Rules = append(policy.Rules, policy.Rules[0])
	if policy.valid() {
		t.Fatal("duplicate rule accepted")
	}
}
