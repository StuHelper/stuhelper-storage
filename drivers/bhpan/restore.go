package bhpan

import (
	"context"
	"strings"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

// Forget discards an invalid provider session without revoking custody consent.
// The same authorized credential revision may then be logged in again.
func (p *Pool) Forget(ref string, revision int64) {
	p.mu.Lock()
	s := p.sessions[ref]
	p.mu.Unlock()
	if s != nil && s.revision == revision {
		p.expire(s)
	}
}

// Restore accepts only a binding obtained from the caller's trusted durable
// instance ledger. It never creates or adopts a caller-selected personal root.
// Ownership of client transfers to the pool only on success.
func (p *Pool) Restore(ctx context.Context, i storage.Instance, client Client) error {
	if client == nil || i.Adapter != "bhpan" || !token.MatchString(i.CredentialRef) || i.CredentialRevision < 1 || !strings.HasPrefix(i.AccountDomain, "bhpan:") || len(i.AccountDomain) != 70 || !i.ExpiresAt.After(time.Now()) {
		return storage.ErrInput
	}
	p.mu.Lock()
	old := p.sessions[i.CredentialRef]
	_, tracked := p.versions[i.CredentialRef]
	if p.closed || (!tracked && len(p.versions) >= 100) || i.CredentialRevision <= p.revoked[i.CredentialRef] || old != nil && (old.revision > i.CredentialRevision || old.root != i.Root || old.account != i.AccountDomain) {
		p.mu.Unlock()
		return storage.ErrDenied
	}
	p.versions[i.CredentialRef]++
	version := p.versions[i.CredentialRef]
	p.mu.Unlock()

	identity, err := client.Identity(ctx)
	if err != nil {
		return safe(err)
	}
	if accountDomain(identity.ID) != i.AccountDomain {
		return storage.ErrDenied
	}
	libraries, err := client.Libraries(ctx)
	if err != nil {
		return safe(err)
	}
	library := ""
	for _, l := range libraries {
		if l.Type == "user_doc_lib" && child(l.ID, i.Root) {
			if library != "" {
				return storage.ErrDenied
			}
			library = l.ID
		}
	}
	if library == "" {
		return storage.ErrDenied
	}
	dir, err := client.List(ctx, library)
	if err != nil {
		return safe(err)
	}
	found := false
	for _, entry := range dir.Directories {
		if entry.ID == i.Root && strings.HasPrefix(entry.Name, "stuhelper-storage-") && intentPattern.MatchString(strings.TrimPrefix(entry.Name, "stuhelper-storage-")) {
			found = true
		}
	}
	if !found {
		return storage.ErrDenied
	}
	p.mu.Lock()
	if ctx.Err() != nil || p.closed || p.versions[i.CredentialRef] != version || !i.ExpiresAt.After(time.Now()) {
		p.mu.Unlock()
		return storage.ErrStale
	}
	sessionCtx, cancel := context.WithDeadline(context.Background(), i.ExpiresAt)
	s := &session{client: client, root: i.Root, library: library, account: i.AccountDomain, ref: i.CredentialRef, revision: i.CredentialRevision, expires: i.ExpiresAt, ctx: sessionCtx, cancel: cancel}
	old = p.sessions[i.CredentialRef]
	p.sessions[i.CredentialRef] = s
	s.timer = time.AfterFunc(time.Until(s.expires), func() { p.expire(s) })
	if old != nil {
		old.cancel()
		old.timer.Stop()
	}
	p.mu.Unlock()
	if old != nil {
		old.client.Close()
	}
	return nil
}
