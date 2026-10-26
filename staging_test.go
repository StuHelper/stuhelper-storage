package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStagingBudgetOwnershipAndRestartCleanup(t *testing.T) {
	dir := t.TempDir()
	s, err := openStaging(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openStaging(dir, 16); !errors.Is(err, ErrConflict) {
		t.Fatalf("second process admitted: %v", err)
	}
	f, err := s.create(12)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.create(5); !errors.Is(err, ErrCapacity) {
		t.Fatal("overbooked disk")
	}
	if _, err := f.Write([]byte("1234567890123")); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unbounded write")
	}
	if _, err := f.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}
	info, err := f.file.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe temporary permissions")
	}
	removeTemporary(f)
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(dir, "storage-staging-v1", "transfer-"+strings.Repeat("a", 32)+".part")
	if err := os.WriteFile(orphan, []byte("crash residue"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "personal-file")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err = openStaging(dir, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("crash residue remains")
	}
	if b, err := os.ReadFile(outside); err != nil || string(b) != "keep" {
		t.Fatal("unrelated file touched")
	}
}
func TestStagingRejectsSymlinkAndForeignContent(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, "storage-staging-v1")
	if err := os.Mkdir(owned, 0700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(owned, "foreign")
	if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStaging(dir, 16); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("removed foreign content")
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(owned, "transfer-"+strings.Repeat("a", 32)+".part")); err != nil {
		t.Fatal(err)
	}
	if _, err := openStaging(dir, 16); !errors.Is(err, ErrConflict) {
		t.Fatal("followed symlink")
	}
}
func TestPacerCancellationAndSharedBudget(t *testing.T) {
	p := newPacer(1000)
	if err := p.wait(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := p.wait(ctx, 100); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rate not shared: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := (&pacedReader{ctx: ctx, src: strings.NewReader("secret"), global: p}).Read(make([]byte, 6)); !errors.Is(err, context.Canceled) {
		t.Fatal("read after cancellation")
	}
}
