package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/StuHelper/stuhelper-storage/storagetest"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
	"github.com/StuHelper/stuhelper-storage/drivers/bhpan"
	"github.com/StuHelper/stuhelper-storage/executor"
)

type protocolFile struct {
	objectID   string
	docID      string
	name       string
	revision   string
	data       []byte
	recycled   bool
	stagedBody []byte
}

type statefulBHpanAccount struct {
	mu          sync.Mutex
	userID      string
	libraryID   string
	directories map[string]string // docID -> name
	files       map[string]*protocolFile
	noiseBin    []protocol.Entry
	seq         int
	purges      int
}

func newStatefulBHpanAccount(userID string, siblingFiles, recycleNoise int) *statefulBHpanAccount {
	lib := "gns://lib-" + userID
	acc := &statefulBHpanAccount{
		userID:      userID,
		libraryID:   lib,
		directories: map[string]string{},
		files:       map[string]*protocolFile{},
	}
	for i := 0; i < recycleNoise; i++ {
		acc.noiseBin = append(acc.noiseBin, protocol.Entry{
			ID:   fmt.Sprintf("%s/recycle-noise-%04d", lib, i),
			Name: fmt.Sprintf("personal-recycled-%04d.pdf", i),
		})
	}
	acc.seq = siblingFiles
	return acc
}

func (a *statefulBHpanAccount) populateRootNoise(root string, count int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := 0; i < count; i++ {
		objID := fmt.Sprintf("sibling-%s-%04d", a.userID, i)
		docID := root + "/" + objID
		a.files[objID] = &protocolFile{
			objectID: objID,
			docID:    docID,
			name:     fmt.Sprintf("existing-%04d.bin", i),
			revision: "rev-0",
			data:     []byte("untouched"),
		}
	}
}

type statefulBHpanClient struct {
	acc    *statefulBHpanAccount
	closed bool
}

func (c *statefulBHpanClient) Identity(context.Context) (protocol.Identity, error) {
	return protocol.Identity{ID: c.acc.userID}, nil
}

func (c *statefulBHpanClient) Libraries(context.Context) ([]protocol.Library, error) {
	return []protocol.Library{{ID: c.acc.libraryID, Type: "user_doc_lib"}}, nil
}

func (c *statefulBHpanClient) Quota(context.Context) (protocol.Quota, error) {
	return protocol.Quota{Allocated: 64 << 20}, nil
}

func (c *statefulBHpanClient) CreateDirectory(_ context.Context, parent, name string) (string, error) {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	c.acc.seq++
	id := fmt.Sprintf("%s/dir-%d", parent, c.acc.seq)
	c.acc.directories[id] = name
	return id, nil
}

func (c *statefulBHpanClient) List(_ context.Context, dirID string) (protocol.Directory, error) {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	out := protocol.Directory{Directories: []protocol.Entry{}, Files: []protocol.Entry{}}
	if dirID == c.acc.libraryID {
		for id, name := range c.acc.directories {
			out.Directories = append(out.Directories, protocol.Entry{ID: id, Name: name})
		}
		return out, nil
	}
	prefix := dirID + "/"
	keys := make([]string, 0, len(c.acc.files))
	for k := range c.acc.files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f := c.acc.files[k]
		if !f.recycled && strings.HasPrefix(f.docID, prefix) {
			out.Files = append(out.Files, protocol.Entry{ID: f.docID, Name: f.name, Revision: f.revision, Size: int64(len(f.data))})
		}
	}
	return out, nil
}

func (c *statefulBHpanClient) FileInfo(_ context.Context, objectID string) (protocol.FileMetadata, error) {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	f, ok := c.acc.files[objectID]
	if !ok {
		return protocol.FileMetadata{}, protocol.ErrNotFound
	}
	return protocol.FileMetadata{
		ObjectID:   f.objectID,
		DocumentID: f.docID,
		Name:       f.name,
		Revision:   f.revision,
		Size:       int64(len(f.data)),
		LibraryID:  strings.TrimPrefix(c.acc.libraryID, "gns://"),
	}, nil
}

func (c *statefulBHpanClient) BeginUpload(_ context.Context, parent, name string, _ int64) (protocol.Upload, error) {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	c.acc.seq++
	objID := fmt.Sprintf("obj-%s-%d", c.acc.userID, c.acc.seq)
	docID := parent + "/" + objID
	rev := fmt.Sprintf("rev-%d", c.acc.seq)
	c.acc.files[objID] = &protocolFile{
		objectID: objID,
		docID:    docID,
		name:     name,
		revision: rev,
	}
	return protocol.Upload{DocumentID: docID, Revision: rev}, nil
}

func (c *statefulBHpanClient) WriteUpload(_ context.Context, u protocol.Upload, src io.Reader) (string, error) {
	body, err := io.ReadAll(src)
	if err != nil {
		return "", err
	}
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	objID := u.DocumentID[strings.LastIndex(u.DocumentID, "/")+1:]
	f, ok := c.acc.files[objID]
	if !ok {
		return "", protocol.ErrNotFound
	}
	f.stagedBody = body
	return "etag-1", nil
}

func (c *statefulBHpanClient) FinishUpload(_ context.Context, docID, rev string) error {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	objID := docID[strings.LastIndex(docID, "/")+1:]
	f, ok := c.acc.files[objID]
	if !ok || f.revision != rev {
		return protocol.ErrConflict
	}
	f.data = append([]byte(nil), f.stagedBody...)
	f.stagedBody = nil
	return nil
}

func (c *statefulBHpanClient) Download(_ context.Context, docID string, dst io.Writer) (int64, error) {
	c.acc.mu.Lock()
	objID := docID[strings.LastIndex(docID, "/")+1:]
	f, ok := c.acc.files[objID]
	var data []byte
	if ok && !f.recycled && f.docID == docID {
		data = append([]byte(nil), f.data...)
	} else {
		ok = false
	}
	c.acc.mu.Unlock()
	if !ok {
		return 0, protocol.ErrNotFound
	}
	n, err := dst.Write(data)
	return int64(n), err
}

func (c *statefulBHpanClient) Delete(_ context.Context, docID string) error {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	objID := docID[strings.LastIndex(docID, "/")+1:]
	f, ok := c.acc.files[objID]
	if !ok || f.recycled {
		return protocol.ErrNotFound
	}
	f.recycled = true
	f.docID = c.acc.libraryID + "/recycled-" + objID
	return nil
}

func (c *statefulBHpanClient) RecycleBin(_ context.Context, libID string, start, limit int) (protocol.Directory, error) {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	if libID != c.acc.libraryID {
		return protocol.Directory{}, protocol.ErrPermission
	}
	all := make([]protocol.Entry, 0, len(c.acc.noiseBin)+len(c.acc.files))
	all = append(all, c.acc.noiseBin...)
	for _, f := range c.acc.files {
		if f.recycled {
			all = append(all, protocol.Entry{ID: f.docID, Name: f.name, Revision: f.revision, Size: int64(len(f.data))})
		}
	}
	if start >= len(all) {
		return protocol.Directory{Directories: []protocol.Entry{}, Files: []protocol.Entry{}}, nil
	}
	end := min(len(all), start+limit)
	return protocol.Directory{Directories: []protocol.Entry{}, Files: all[start:end]}, nil
}

func (c *statefulBHpanClient) Purge(_ context.Context, docID string) error {
	c.acc.mu.Lock()
	defer c.acc.mu.Unlock()
	for objID, f := range c.acc.files {
		if f.recycled && f.docID == docID {
			delete(c.acc.files, objID)
			c.acc.purges++
			return nil
		}
	}
	return protocol.ErrNotFound
}

func (c *statefulBHpanClient) Close() { c.closed = true }

func TestServiceExecutorAndBHpanPoolRestartAndPopulatedDirectoryIntegration(t *testing.T) {
	h := harnessFor(t)
	tempDir := t.TempDir()
	baseCfg := storage.Config{
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: tempDir,
		ParallelTransfers:  4,
		Lease:              time.Minute,
		VerificationAge:    time.Hour,
		QuotaValidity:      10 * time.Minute,
		MaxAttempts:        3,
	}

	pool1 := bhpan.NewPool()
	svc1, err := storage.New(h.repo, h.auth, pool1, pool1, baseCfg)
	if err != nil {
		t.Fatal(err)
	}

	accounts := map[string]*statefulBHpanAccount{}
	until := time.Now().UTC().Add(2 * time.Hour)
	for idx, ref := range []string{"bhpan-node-1", "bhpan-node-2", "bhpan-node-3"} {
		acc := newStatefulBHpanAccount(fmt.Sprintf("buaa-student-%d", idx+1), 120, 1250)
		accounts[ref] = acc
		provisioned, err := pool1.Provision(h.ctx, ref, 1, &statefulBHpanClient{acc: acc}, until)
		if err != nil {
			t.Fatal(err)
		}
		// Populate 120 sibling entries inside the isolated directory and 1,250 items in recycle bin.
		acc.populateRootNoise(provisioned.Root, 120)

		provisioned.ID = ref
		provisioned.OwnerDomain = "owner-" + ref
		provisioned.Ownership = "contributor"
		provisioned.State = "active"
		provisioned.Authorized = true
		provisioned.Limit = 16 << 20
		provisioned.Admissions = []storage.Admission{{
			Class:     "public",
			Scope:     "school-a",
			Plaintext: true,
			ExpiresAt: until,
		}}
		if _, err := storagetest.RegisterContribution(h.ctx, svc1, h.actor, "reg-"+ref, provisioned); err != nil {
			t.Fatal(err)
		}
	}

	payload := bytes.Repeat([]byte("bhpan-e2e-course-archive-"), 512)
	sum := sha256.Sum256(payload)
	created, err := svc1.Create(h.ctx, h.actor, "create-e2e", storage.CreateRequest{
		Size:       int64(len(payload)),
		SHA256:     hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc1.Ingest(h.ctx, h.actor, created.ID, "upload-e2e", bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	// Enqueue replication jobs onto the remaining two BHpan accounts before shutdown.
	if _, err := svc1.Reconcile(h.ctx, h.actor, 50, ""); err != nil {
		t.Fatal(err)
	}

	// Simulate graceful process stop and pool teardown before replication jobs run.
	if err := svc1.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	pool1.Close()

	// Cold restart: new Pool + new Service + Executor restoring sessions from durable PostgreSQL ledger.
	pool2 := bhpan.NewPool()
	defer pool2.Close()
	svc2, err := storage.New(h.repo, h.auth, pool2, pool2, baseCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc2.Close(context.Background()) }()

	durableInstances, err := svc2.Instances(h.ctx, h.actor, 100, "")
	if err != nil || len(durableInstances) != 3 {
		t.Fatalf("expected 3 durable instances, got %d (%v)", len(durableInstances), err)
	}
	for _, inst := range durableInstances {
		if err := pool2.Restore(h.ctx, inst, &statefulBHpanClient{acc: accounts[inst.CredentialRef]}); err != nil {
			t.Fatalf("Restore(%s) failed: %v", inst.ID, err)
		}
	}

	exec2, err := executor.New(svc2, executor.Config{
		ID:                  "bhpan_e2e",
		Principal:           h.actor,
		Workers:             2,
		PollInterval:        50 * time.Millisecond,
		MaintenanceInterval: 2 * time.Second,
		MaintenanceTimeout:  5 * time.Second,
		QuotaRefreshAhead:   time.Minute,
		BatchSize:           20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec2.Start(h.ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = exec2.Stop(stopCtx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var readyStatus storage.Status
	for {
		readyStatus, err = svc2.Status(h.ctx, h.actor, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if readyStatus.Healthy == 3 && readyStatus.State == "ready" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replicas did not reach 3/3 ready after cold restore: %+v", readyStatus)
		}
		time.Sleep(15 * time.Millisecond)
	}

	var downloaded bytes.Buffer
	if err := svc2.Download(h.ctx, h.actor, created.ID, &downloaded); err != nil || !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatalf("downloaded bytes mismatch: %v", err)
	}

	// Delete object and verify multi-page RecycleBin (>1000 items) scan + permanent Purge across all 3 accounts.
	delStatus, err := svc2.Delete(h.ctx, h.actor, created.ID, "delete-e2e", readyStatus.Revision)
	if err != nil || delStatus.State != "deleting" {
		t.Fatalf("unexpected delete status: %+v %v", delStatus, err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		st, err := svc2.Status(h.ctx, h.actor, created.ID)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == "deleted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replicas were not permanently purged across populated recycle bins: %+v", st)
		}
		time.Sleep(15 * time.Millisecond)
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := exec2.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}

	finalInstances, err := svc2.Instances(h.ctx, h.actor, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range finalInstances {
		if inst.Used != 0 || inst.Reserved != 0 {
			t.Fatalf("instance %s leaked ledger bytes: used=%d reserved=%d", inst.ID, inst.Used, inst.Reserved)
		}
		acc := accounts[inst.CredentialRef]
		acc.mu.Lock()
		remainingFiles := len(acc.files)
		purges := acc.purges
		noiseBin := len(acc.noiseBin)
		acc.mu.Unlock()
		if purges != 1 || remainingFiles != 120 || noiseBin != 1250 {
			t.Fatalf("account %s unexpected remote state: purges=%d remainingFiles=%d noiseBin=%d", inst.ID, purges, remainingFiles, noiseBin)
		}
	}
}
