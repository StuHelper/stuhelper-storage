package storage_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/custody"
	"github.com/StuHelper/stuhelper-storage/postgres"
)

type custodyAuth struct{ denied atomic.Bool }

func (a *custodyAuth) Authorize(_ context.Context, p storage.Principal, action, _ string, _ storage.Protection) error {
	if a.denied.Load() || p.Subject == "foreign" && action != "storage.custody.read" || strings.Contains(action, "operations") && p.Subject != "admin" || !strings.Contains(action, "operations") && p.Subject == "admin" {
		return storage.ErrDenied
	}
	return nil
}

type custodyProvider struct {
	h           *harness
	creates     atomic.Int32
	failCommit  atomic.Bool
	failPrepare atomic.Bool
	account     string
}

func (p *custodyProvider) Fingerprint(b []byte) (string, error) {
	m := hmac.New(sha256.New, []byte("fixture-private-mac"))
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil)), nil
}
func (p *custodyProvider) ValidateInput(string, json.RawMessage) error { return nil }
func (p *custodyProvider) Prepare(ctx context.Context, id string, until time.Time, _ json.RawMessage, current *storage.Instance, claim func(string) error) (storage.Instance, error) {
	if p.failPrepare.Load() {
		return storage.Instance{}, storage.ErrDenied
	}
	if current != nil {
		i := *current
		i.CredentialRevision++
		i.ExpiresAt = until
		return i, nil
	}
	ref := "custody-" + id
	account := p.account
	if account == "" {
		account = "account:" + ref
	}
	if e := claim(account); e != nil {
		return storage.Instance{}, e
	}
	p.h.provider.mu.Lock()
	p.h.provider.accounts[ref] = account
	p.h.provider.mu.Unlock()
	p.creates.Add(1)
	return storage.Instance{Adapter: "bhpan", CredentialRef: ref, CredentialRevision: 1, AccountDomain: account, Root: "dedicated-root", ExpiresAt: until}, nil
}
func (p *custodyProvider) Resume(ctx context.Context, id string, until time.Time, current *storage.Instance, claim func(string) error) (storage.Instance, error) {
	return p.Prepare(ctx, id, until, nil, current, claim)
}
func (p *custodyProvider) Commit(context.Context, storage.Instance) error {
	if p.failCommit.Load() {
		return storage.ErrUnavailable
	}
	return nil
}
func custodyFixture(t *testing.T) (*harness, *custody.Service, *custodyProvider, *custodyAuth, storage.Principal, custody.Request) {
	h := harnessFor(t)
	provider := &custodyProvider{h: h}
	auth := &custodyAuth{}
	s, e := custody.New(&postgres.CustodyRepository{Repository: h.repo}, auth, h.s, provider, custody.Config{Actor: h.actor, Policy: custody.Policy{Version: "custody-v1", Digest: strings.Repeat("a", 64), URL: "https://example.invalid/custody", MaxTermSeconds: 86400 * 30}, PublicScopes: []string{"school-a"}, Clock: h.clock.Now, Timeout: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	q := custody.Request{Adapter: "bhpan", Credential: json.RawMessage(`{"mode":"local","username":"fixture","password":"test-only-value"}`), Until: h.clock.Now().Add(24 * time.Hour), Consent: custody.Consent{Accepted: true, Version: "custody-v1", Digest: strings.Repeat("a", 64)}}
	return h, s, provider, auth, storage.Principal{Issuer: "test-issuer", Subject: "user"}, q
}
func TestCustodyConsentOwnershipIdempotencyAndIsolation(t *testing.T) {
	h, s, p, a, user, q := custodyFixture(t)
	key := "00000000-0000-4000-8000-000000000001"
	bad := q
	bad.Consent.Accepted = false
	if _, e := s.Submit(h.ctx, user, "", key, bad); !errors.Is(e, storage.ErrInput) {
		t.Fatal(e)
	}
	v, e := s.Submit(h.ctx, user, "", key, q)
	if e != nil || v.State != "ready" {
		t.Fatal(v, e)
	}
	rows, e := h.s.Instances(h.ctx, h.actor, 100, "")
	if e != nil || len(rows) != 1 || rows[0].State != "paused" || rows[0].Limit != 0 || rows[0].OwnerDomain != custody.OwnerDomain(user) {
		t.Fatal("enrollment started contribution", e)
	}
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			again, e := s.Submit(h.ctx, user, "", key, q)
			if e != nil || again != v {
				t.Error(again, e)
			}
		}()
	}
	wg.Wait()
	if p.creates.Load() != 1 {
		t.Fatal("duplicate remote roots")
	}
	bad = q
	bad.Credential = json.RawMessage(`{"password":"changed"}`)
	if _, e = s.Submit(h.ctx, user, "", key, bad); !errors.Is(e, storage.ErrConflict) {
		t.Fatal(e)
	}
	foreign := storage.Principal{Issuer: user.Issuer, Subject: "foreign"}
	if _, e = s.GetRequest(h.ctx, foreign, key); !errors.Is(e, storage.ErrDenied) {
		t.Fatal(e)
	}
	page, e := s.List(h.ctx, foreign, 20, "", false)
	if e != nil || len(page.Items) != 0 {
		t.Fatal(e, page)
	}
	if _, e = s.List(h.ctx, user, 20, "", true); !errors.Is(e, storage.ErrDenied) {
		t.Fatal(e)
	}
	page, e = s.List(h.ctx, storage.Principal{Issuer: user.Issuer, Subject: "admin"}, 20, "", true)
	if e != nil || len(page.Items) != 1 {
		t.Fatal(e)
	}
	serialized, _ := json.Marshal(page)
	for _, secret := range []string{"password", "username", "credential_ref", "dedicated-root", "account_domain"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatal("private metadata leaked")
		}
	}
	var persisted string
	if e = h.db.QueryRow(`SELECT data::text FROM storage.custody_operations WHERE id=$1`, key).Scan(&persisted); e != nil || strings.Contains(persisted, "test-only-value") {
		t.Fatal("secret entered ledger", e)
	}
	if _, e = h.db.Exec(`SELECT * FROM other_module.private_data`); e == nil {
		t.Fatal("runtime crossed module boundary")
	}
	a.denied.Store(true)
	if _, e = s.GetRequest(h.ctx, user, key); !errors.Is(e, storage.ErrDenied) {
		t.Fatal(e)
	}
}
func TestCustodyRecoveryAndRenewalPreserveExistingInstance(t *testing.T) {
	h, s, p, _, user, q := custodyFixture(t)
	key := "00000000-0000-4000-8000-000000000002"
	p.failCommit.Store(true)
	v, e := s.Submit(h.ctx, user, "", key, q)
	if e != nil || v.State != "blocked" {
		t.Fatal(v, e)
	}
	p.failCommit.Store(false)
	v, e = s.Resume(h.ctx, user, v.ID, custody.ResumeRequest{RequestID: key, Revision: v.Revision}, false)
	if e != nil || v.State != "ready" || p.creates.Load() != 1 {
		t.Fatal("recovery repeated provision", v, e)
	}
	rows, _ := h.s.Instances(h.ctx, h.actor, 100, "")
	old := rows[0]
	c := storage.ContributionControl{ID: "contribution", OwnerDomain: old.OwnerDomain, Revision: 1, ExpectedRevision: old.Revision, State: "active", LimitBytes: 1024, PersonalReserve: 100, Until: q.Until}
	if _, e = h.s.ApplyContribution(h.ctx, h.actor, old.ID, c); e != nil {
		t.Fatal(e)
	}
	rows, _ = h.s.Instances(h.ctx, h.actor, 100, "")
	old = rows[0]
	q.Revision = v.Revision
	q.Until = q.Until.Add(time.Hour)
	p.failPrepare.Store(true)
	v, e = s.Submit(h.ctx, user, v.ID, "00000000-0000-4000-8000-000000000003", q)
	if e != nil || v.State != "credentials_required" {
		t.Fatal(v, e)
	}
	rows, _ = h.s.Instances(h.ctx, h.actor, 100, "")
	if !reflect.DeepEqual(old, rows[0]) {
		t.Fatal("failed renewal changed live instance")
	}
	p.failPrepare.Store(false)
	q.Revision = v.Revision
	v, e = s.Submit(h.ctx, user, v.ID, "00000000-0000-4000-8000-000000000004", q)
	if e != nil || v.State != "ready" {
		t.Fatal(v, e)
	}
	rows, _ = h.s.Instances(h.ctx, h.actor, 100, "")
	next := rows[0]
	if next.CredentialRevision != old.CredentialRevision+1 || !next.ExpiresAt.Equal(q.Until) {
		t.Fatal("credential not advanced")
	}
	next.CredentialRevision = old.CredentialRevision
	next.ExpiresAt = old.ExpiresAt
	next.Revision = old.Revision
	if !reflect.DeepEqual(old, next) {
		t.Fatal("renewal modified contribution, admissions, root or quota")
	}
}
func TestCustodyDuplicateAccountsClaimsAndPagination(t *testing.T) {
	h, s, p, _, user, q := custodyFixture(t)
	p.account = "account:stable"
	for n := 1; n <= 2; n++ {
		key := fmt.Sprintf("10000000-0000-4000-8000-%012d", n)
		v, e := s.Submit(h.ctx, user, "", key, q)
		if e != nil || n == 1 && v.State != "ready" || n == 2 && v.LastError != "conflict" {
			t.Fatal(v, e)
		}
	}
	if p.creates.Load() != 1 {
		t.Fatal("duplicate account created root")
	}
	page, e := s.List(h.ctx, user, 1, "", false)
	if e != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatal(page, e)
	}
	page, e = s.List(h.ctx, user, 1, page.NextCursor, false)
	if e != nil || len(page.Items) != 1 || page.NextCursor != "" {
		t.Fatal(page, e)
	}
}
