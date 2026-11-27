package custody

import (
	"context"
	"strings"

	storage "github.com/StuHelper/stuhelper-storage"
)

// DirectoryIntent is private provider metadata. Never copy it into a public View.
type DirectoryIntent struct {
	Library        string
	Name           string
	Root           string
	ReviewRequired bool `json:",omitempty"`
}

type directoryRecorderKey struct{}
type directoryRecorder func(account string, intent DirectoryIntent) error

// RecordDirectoryIntent checkpoints the provider write in the online custody
// ledger. Standalone provisioning persists its own intent in the private vault.
func RecordDirectoryIntent(ctx context.Context, account string, intent DirectoryIntent) error {
	record, ok := ctx.Value(directoryRecorderKey{}).(directoryRecorder)
	if !ok {
		return nil
	}
	return record(account, intent)
}

func (s *Service) directoryRecorder(ctx context.Context, target string, op Operation) directoryRecorder {
	return func(account string, intent DirectoryIntent) error {
		if !id.MatchString(account) || intent.Library == "" || len(intent.Library) > 1024 || intent.Name == "" || len(intent.Name) > 255 || strings.ContainsAny(intent.Name, "/\\\x00") {
			return storage.ErrInput
		}
		if intent.Root != "" {
			child, ok := strings.CutPrefix(intent.Root, intent.Library+"/")
			if !ok || child == "" || strings.Contains(child, "/") || len(intent.Root) > 1024 {
				return storage.ErrInput
			}
		}
		return s.repo.Transaction(ctx, func(tx Tx) error {
			latest, err := tx.Operation(op.ID)
			if err != nil {
				return err
			}
			if latest.Attempts != op.Attempts || !latest.LeaseUntil.After(s.cfg.Clock()) {
				return storage.ErrStale
			}
			b, err := tx.Binding(target)
			if err != nil {
				return err
			}
			if b.RequestID != op.ID || b.AccountDomain != account || b.Instance.ID != "" {
				return storage.ErrConflict
			}
			if prior := b.DirectoryIntent; prior != nil {
				intent.ReviewRequired = prior.ReviewRequired
				if prior.Library != intent.Library || prior.Name != intent.Name || prior.Root != "" && prior.Root != intent.Root {
					return storage.ErrConflict
				}
			}
			b.DirectoryIntent = &intent
			return tx.SaveBinding(b)
		})
	}
}
