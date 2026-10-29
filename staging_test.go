package storage

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStagingProcessCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := func() *exec.Cmd {
		c := exec.Command(binary, "-test.run=^TestStagingProcessHelper$")
		c.Env = append(os.Environ(), "STUHELPER_STAGING_HELPER="+dir)
		return c
	}
	active, err := openStaging(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err = command().Run(); !errors.As(err, &exit) || exit.ExitCode() != 17 {
		t.Fatalf("child ignored live directory lock: %v", err)
	}
	if err = active.close(); err != nil {
		t.Fatal(err)
	}
	// The child exits without releasing its temporary file or calling Close.
	if output, err := command().CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, output)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "storage-staging-v1"))
	if err != nil || len(entries) != 2 {
		t.Fatal("no process-exit residue", err)
	}
	recovered, err := openStaging(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.close()
	entries, err = os.ReadDir(filepath.Join(dir, "storage-staging-v1"))
	if err != nil || len(entries) != 1 || entries[0].Name() != ".lock" {
		t.Fatal("process-exit residue not recovered", err)
	}
}

func TestStagingProcessHelper(t *testing.T) {
	dir := os.Getenv("STUHELPER_STAGING_HELPER")
	if dir == "" {
		return
	}
	s, err := openStaging(dir, 64)
	if errors.Is(err, ErrConflict) {
		os.Exit(17)
	}
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.create(64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("unfinished transfer")); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

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
