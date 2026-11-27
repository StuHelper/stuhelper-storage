package bhpan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
)

const rootPrefix = "【严禁自行删除！StuHelper贡献空间 严禁自行删除！】"

// NewRootName is issued at enrollment, before the owner declares a capacity.
func NewRootName() (string, error) {
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", storage.ErrUnavailable
	}
	return rootPrefix + hex.EncodeToString(nonce[:]), nil
}

func rootIdentifier(name string) string {
	if suffix, ok := strings.CutPrefix(name, "stuhelper-storage-"); ok && intentPattern.MatchString(suffix) {
		return suffix
	}
	if suffix, ok := strings.CutPrefix(name, rootPrefix); ok && len(suffix) == 8 {
		if _, err := hex.DecodeString(suffix); err == nil && strings.ToLower(suffix) == suffix {
			return suffix
		}
	}
	return ""
}

// IsManagedRootName accepts newly provisioned and established legacy names.
func IsManagedRootName(name string) bool { return rootIdentifier(name) != "" }

// MigrateRootName uses only the trusted binding and its existing session.
// Read-before-write also reconciles a successful rename whose reply was lost.
func (p *Pool) MigrateRootName(ctx context.Context, i storage.Instance) error {
	s, err := p.get(i)
	if err != nil {
		return err
	}
	if i.Ownership != "contributor" || !i.Authorized || i.AccountDomain != s.account || i.State == "revoked" || i.ClosureDraining || !i.ExpiresAt.After(time.Now()) {
		return storage.ErrDenied
	}
	work, done := s.operation(ctx)
	defer done()
	listing, err := s.client.List(work, s.library)
	if err != nil {
		return s.safeErr(ctx, "list", err)
	}
	for _, entry := range listing.Directories {
		if entry.ID != s.root {
			continue
		}
		suffix := rootIdentifier(entry.Name)
		if suffix == "" {
			return storage.ErrDenied
		}
		target := rootPrefix + suffix[:8]
		if target == entry.Name {
			return nil
		}
		client, ok := s.client.(interface {
			Rename(context.Context, string, string) error
		})
		if !ok {
			return storage.ErrUnavailable
		}
		if err := client.Rename(work, s.root, target); err != nil {
			return s.safeErr(ctx, "rename", err)
		}
		after, err := s.client.List(work, s.library)
		if err != nil {
			return s.safeErr(ctx, "list", err)
		}
		for _, confirmed := range after.Directories {
			if confirmed.ID == s.root && confirmed.Name == target {
				return nil
			}
		}
		return storage.ErrUnknown
	}
	return storage.ErrDenied
}
