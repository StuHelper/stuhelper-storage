package storage

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// staging exclusively owns one private directory. Reservations are released
// only after unlink succeeds, so failed cleanup cannot silently exceed budget.
type staging struct {
	mu              sync.Mutex
	root            *os.Root
	lock            *os.File
	limit, reserved int64
	files           map[*stagedFile]int64
}
type stagedFile struct {
	file      *os.File
	owner     *staging
	name      string
	remaining int64
	once      sync.Once
}

var stagingName = regexp.MustCompile(`^transfer-[a-f0-9]{32}\.part$`)

func openStaging(parent string, limit int64) (*staging, error) {
	if !filepath.IsAbs(parent) {
		return nil, ErrInput
	}
	base, err := os.OpenRoot(parent)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer base.Close()
	if err = base.Mkdir("storage-staging-v1", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrUnavailable
	}
	info, err := base.Lstat("storage-staging-v1")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrInput
	}
	root, err := base.OpenRoot("storage-staging-v1")
	if err != nil {
		return nil, ErrUnavailable
	}
	s := &staging{root: root, limit: limit, files: map[*stagedFile]int64{}}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	if info, e := root.Lstat(".lock"); e == nil && !info.Mode().IsRegular() {
		return nil, ErrInput
	}
	s.lock, err = root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err = lockStaging(s.lock); err != nil {
		return nil, ErrConflict
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, ErrUnavailable
	}
	defer dir.Close()
	// Bound startup inspection; no recursive traversal or deletion is allowed.
	entries, err := dir.ReadDir(10001)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrUnavailable
	}
	if len(entries) > 10000 {
		return nil, ErrCapacity
	}
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		if !stagingName.MatchString(entry.Name()) {
			return nil, ErrConflict
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrConflict
		}
	}
	for _, entry := range entries {
		if entry.Name() != ".lock" {
			if err = root.Remove(entry.Name()); err != nil {
				return nil, ErrUnavailable
			}
		}
	}
	ok = true
	return s, nil
}
func (s *staging) create(size int64) (*stagedFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil, ErrUnavailable
	}
	if size < 1 || size > s.limit-s.reserved {
		return nil, ErrCapacity
	}
	name := "transfer-" + newID() + ".part"
	f, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	v := &stagedFile{file: f, owner: s, name: name, remaining: size}
	s.files[v] = size
	s.reserved += size
	return v, nil
}
func (f *stagedFile) Read(p []byte) (int, error) { return f.file.Read(p) }
func (f *stagedFile) Seek(offset int64, whence int) (int64, error) {
	return f.file.Seek(offset, whence)
}
func (f *stagedFile) Write(p []byte) (int, error) {
	if int64(len(p)) > f.remaining {
		return 0, ErrIntegrity
	}
	n, err := f.file.Write(p)
	f.remaining -= int64(n)
	return n, err
}
func removeTemporary(f *stagedFile) {
	if f == nil {
		return
	}
	f.once.Do(func() {
		_ = f.file.Close()
		s := f.owner
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.root != nil && s.root.Remove(f.name) == nil {
			s.reserved -= s.files[f]
			delete(s.files, f)
		}
	})
}
func (s *staging) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	if len(s.files) > 0 {
		return ErrUnavailable
	}
	err := s.root.Close()
	s.root = nil
	if s.lock != nil {
		if e := s.lock.Close(); err == nil {
			err = e
		}
		s.lock = nil
	}
	return err
}
