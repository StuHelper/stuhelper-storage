package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	protocol "github.com/StuHelper/stuhelper-storage-bhpan"
	"github.com/StuHelper/stuhelper-storage/drivers/bhpan"
	"github.com/StuHelper/stuhelper-storage/postgres"
)

type bhpanFakeClient struct {
	mu             sync.Mutex
	account        string
	root           string
	dirs           map[string]string
	files          map[string]bhpanFakeFile
	recycled       map[string]bhpanFakeFile
	seq            int
	rootLists      atomic.Int32
	shardLists     atomic.Int32
	failRootList   atomic.Bool
	failShardSetup atomic.Bool
	lostBegin      atomic.Bool
	beforeDownload func(context.Context) error
}

type bhpanFakeFile struct {
	objectID   string
	documentID string
	parent     string
	name       string
	revision   string
	data       []byte
}

func newBHpanFakeClient(account string) *bhpanFakeClient {
	return &bhpanFakeClient{
		account:  account,
		dirs:     map[string]string{},
		files:    map[string]bhpanFakeFile{},
		recycled: map[string]bhpanFakeFile{},
	}
}

func (c *bhpanFakeClient) Identity(ctx context.Context) (protocol.Identity, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Identity{}, err
	}
	return protocol.Identity{ID: c.account}, nil
}

func (c *bhpanFakeClient) Libraries(ctx context.Context) ([]protocol.Library, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []protocol.Library{{ID: "gns://lib-" + c.account, Type: "user_doc_lib"}}, nil
}

func (c *bhpanFakeClient) Quota(ctx context.Context) (protocol.Quota, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Quota{}, err
	}
	return protocol.Quota{Allocated: 1 << 30, Used: 0}, nil
}

func (c *bhpanFakeClient) CreateDirectory(ctx context.Context, parent, name string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.HasPrefix(parent, "gns://lib-") && !strings.Contains(strings.TrimPrefix(parent, "gns://"), "/") {
		c.seq++
		c.root = fmt.Sprintf("%s/root-%d", parent, c.seq)
		c.dirs[c.root] = name
		return c.root, nil
	}
	if c.failShardSetup.Load() {
		return "", protocol.ErrUnavailable
	}
	for id, existingName := range c.dirs {
		if strings.HasPrefix(id, parent+"/") && !strings.Contains(strings.TrimPrefix(id, parent+"/"), "/") && existingName == name {
			return "", protocol.ErrConflict
		}
	}
	c.seq++
	id := fmt.Sprintf("%s/dir-%d", parent, c.seq)
	c.dirs[id] = name
	return id, nil
}

func (c *bhpanFakeClient) List(ctx context.Context, id string) (protocol.Directory, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Directory{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := protocol.Directory{Directories: []protocol.Entry{}, Files: []protocol.Entry{}}
	if id == "gns://lib-"+c.account {
		if c.root != "" {
			out.Directories = append(out.Directories, protocol.Entry{ID: c.root, Name: c.dirs[c.root]})
		}
		return out, nil
	}
	if id == c.root {
		c.rootLists.Add(1)
		if c.failRootList.Load() {
			return protocol.Directory{}, protocol.ErrProtocol
		}
	} else {
		c.shardLists.Add(1)
	}
	for dirID, name := range c.dirs {
		if strings.HasPrefix(dirID, id+"/") && !strings.Contains(strings.TrimPrefix(dirID, id+"/"), "/") {
			out.Directories = append(out.Directories, protocol.Entry{ID: dirID, Name: name})
		}
	}
	for _, f := range c.files {
		if f.parent == id {
			out.Files = append(out.Files, protocol.Entry{ID: f.documentID, Name: f.name, Revision: f.revision, Size: int64(len(f.data))})
		}
	}
	return out, nil
}

func (c *bhpanFakeClient) FileInfo(ctx context.Context, objectID string) (protocol.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return protocol.FileMetadata{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.files[objectID]; ok {
		return protocol.FileMetadata{ObjectID: f.objectID, DocumentID: f.documentID, Name: f.name, Revision: f.revision, Size: int64(len(f.data)), LibraryID: "lib-" + c.account}, nil
	}
	if f, ok := c.recycled[objectID]; ok {
		return protocol.FileMetadata{ObjectID: f.objectID, DocumentID: f.documentID, Name: f.name, Revision: f.revision, Size: int64(len(f.data)), LibraryID: "lib-" + c.account}, nil
	}
	return protocol.FileMetadata{}, protocol.ErrNotFound
}

func (c *bhpanFakeClient) BeginUpload(ctx context.Context, parent, name string, _ int64) (protocol.Upload, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Upload{}, err
	}
	c.mu.Lock()
	c.seq++
	objID := fmt.Sprintf("obj-%d", c.seq)
	docID := parent + "/" + objID
	rev := "rev-1"
	c.files[objID] = bhpanFakeFile{objectID: objID, documentID: docID, parent: parent, name: name, revision: rev}
	lost := c.lostBegin.Load()
	c.mu.Unlock()
	if lost {
		return protocol.Upload{}, protocol.ErrUnavailable
	}
	return protocol.Upload{DocumentID: docID, Revision: rev}, nil
}

func (c *bhpanFakeClient) WriteUpload(ctx context.Context, u protocol.Upload, src io.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data, err := io.ReadAll(src)
	if err != nil {
		return "", err
	}
	objID := u.DocumentID[strings.LastIndex(u.DocumentID, "/")+1:]
	c.mu.Lock()
	f := c.files[objID]
	f.data = data
	c.files[objID] = f
	c.mu.Unlock()
	return "etag", nil
}

func (c *bhpanFakeClient) FinishUpload(ctx context.Context, _, _ string) error {
	return ctx.Err()
}

func (c *bhpanFakeClient) Download(ctx context.Context, docID string, dst io.Writer) (int64, error) {
	if c.beforeDownload != nil {
		if err := c.beforeDownload(ctx); err != nil {
			return 0, err
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	objID := docID[strings.LastIndex(docID, "/")+1:]
	c.mu.Lock()
	f, ok := c.files[objID]
	data := bytes.Clone(f.data)
	c.mu.Unlock()
	if !ok {
		return 0, protocol.ErrNotFound
	}
	n, err := dst.Write(data)
	return int64(n), err
}

func (c *bhpanFakeClient) Delete(ctx context.Context, docID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	objID := docID[strings.LastIndex(docID, "/")+1:]
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.files[objID]
	if !ok {
		return protocol.ErrNotFound
	}
	delete(c.files, objID)
	f.documentID = "gns://recycle-" + c.account + "/" + objID
	c.recycled[objID] = f
	return nil
}

func (c *bhpanFakeClient) RecycleBin(ctx context.Context, _ string, start, _ int) (protocol.Directory, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Directory{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := protocol.Directory{Directories: []protocol.Entry{}, Files: []protocol.Entry{}}
	if start > 0 {
		return out, nil
	}
	for _, f := range c.recycled {
		out.Files = append(out.Files, protocol.Entry{ID: f.documentID, Name: f.name, Revision: f.revision})
	}
	return out, nil
}

func (c *bhpanFakeClient) Purge(ctx context.Context, docID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	objID := docID[strings.LastIndex(docID, "/")+1:]
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.recycled, objID)
	return nil
}

func (c *bhpanFakeClient) Close() {}

func newBHpanRecoveryHarness(t *testing.T) (*harness, *bhpanFakeClient, *bhpanFakeClient) {
	t.Helper()
	if os.Getenv("STUHELPER_STORAGE_TEST_DSN") == "" {
		t.Skip("PostgreSQL integration requires STUHELPER_STORAGE_TEST_DSN")
	}
	base := harnessFor(t)
	pool := bhpan.NewPool()
	t.Cleanup(pool.Close)

	now := time.Now().UTC()
	c := &clock{now: now}
	cfg := storage.Config{
		Clock:              c.Now,
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: t.TempDir(),
		ParallelTransfers:  4,
		Lease:              2 * time.Minute,
		VerificationAge:    time.Minute,
		MaxAttempts:        3,
	}
	repo := &postgres.Repository{DB: base.db}
	svc, err := storage.New(repo, base.auth, pool, pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	clientA := newBHpanFakeClient("acct-a")
	clientB := newBHpanFakeClient("acct-b")
	expires := now.Add(2 * time.Hour)
	for idx, cl := range []*bhpanFakeClient{clientA, clientB} {
		id := fmt.Sprintf("bhpan-%d", idx+1)
		prov, err := pool.Provision(base.ctx, id, 1, cl, expires)
		if err != nil {
			t.Fatal(err)
		}
		prov.ID = id
		prov.OwnerDomain = id
		prov.Ownership = "platform"
		prov.State = "active"
		prov.Authorized = true
		prov.Limit = 1 << 20
		prov.Admissions = []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: expires}}
		if _, err = svc.Register(base.ctx, base.actor, "reg-"+id, prov); err != nil {
			t.Fatal(err)
		}
	}

	base.s, base.repo, base.clock = svc, repo, c
	return base, clientA, clientB
}
func TestBHpanShutdownCancellationRecoversWithoutBlockingJob(t *testing.T) {
	base, clientA, clientB := newBHpanRecoveryHarness(t)
	svc, repo, c := base.s, base.repo, base.clock
	payload := []byte("bhpan shutdown recovery payload")
	sum := sha256.Sum256(payload)
	obj, err := svc.Create(base.ctx, base.actor, "create", storage.CreateRequest{
		Size:       int64(len(payload)),
		SHA256:     hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientA.failShardSetup.Store(true)
	clientB.failShardSetup.Store(true)
	if _, err = svc.Ingest(base.ctx, base.actor, obj.ID, "ingest", bytes.NewReader(payload)); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("initial setup: %v", err)
	}
	clientA.failShardSetup.Store(false)
	clientB.failShardSetup.Store(false)
	if _, err = svc.Ingest(base.ctx, base.actor, obj.ID, "ingest", bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Reconcile(base.ctx, base.actor, 100, ""); err != nil {
		t.Fatal(err)
	}

	// Simulate rolling shutdown cancelling worker context during source read on BHpan.
	entered := make(chan struct{})
	var cancelOnce sync.Once
	workerCtx, cancelWorker := context.WithCancel(base.ctx)
	hook := func(ctx context.Context) error {
		cancelOnce.Do(func() {
			close(entered)
			cancelWorker()
		})
		<-ctx.Done()
		return ctx.Err()
	}
	clientA.beforeDownload = hook
	clientB.beforeDownload = hook

	claimed, err := svc.RunOne(workerCtx, "worker-1")
	if !claimed || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled replicate job, claimed=%v err=%v", claimed, err)
	}
	clientA.beforeDownload = nil
	clientB.beforeDownload = nil

	ops, err := svc.Operations(base.ctx, base.actor, 100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if ops.Jobs.Blocked != 0 || ops.Jobs.Pending != 1 {
		t.Fatalf("shutdown cancellation permanently blocked job: jobs=%+v failures=%+v", ops.Jobs, ops.Failures)
	}

	c.Add(6 * time.Second)
	clientA.failShardSetup.Store(true)
	clientB.failShardSetup.Store(true)
	if claimed, err = svc.RunOne(base.ctx, "shard-worker"); !claimed || !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("expected transient shard failure: %t %v", claimed, err)
	}
	if err = repo.Transaction(base.ctx, func(tx storage.Transaction) error {
		copies, e := tx.Replicas(obj.ID)
		if e != nil {
			return e
		}
		var reserved int
		for _, copy := range copies {
			if copy.Reserved {
				reserved++
				if copy.IssuedWrite || copy.Remote.ID != "" {
					t.Fatal("shard setup marked a remote write as issued")
				}
			}
		}
		if reserved != 1 {
			t.Fatalf("reserved replicas: %d", reserved)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clientA.failShardSetup.Store(false)
	clientB.failShardSetup.Store(false)
	c.Add(12 * time.Second)
	if claimed, err = svc.RunOne(base.ctx, "worker-2"); !claimed || err != nil {
		t.Fatalf("restart worker failed to finish replicate: claimed=%v err=%v", claimed, err)
	}
	st, err := svc.Status(base.ctx, base.actor, obj.ID)
	if err != nil || st.Healthy != 2 {
		t.Fatalf("expected 2 healthy replicas after recovery, got %+v err=%v", st, err)
	}

	// Advance past half of VerificationAge so periodic verify jobs are scheduled, then cancel verify mid-flight.
	c.Add(31 * time.Second)
	if _, err = svc.Reconcile(base.ctx, base.actor, 100, ""); err != nil {
		t.Fatal(err)
	}
	verifyCtx, cancelVerify := context.WithCancel(base.ctx)
	var verifyOnce sync.Once
	verifyHook := func(ctx context.Context) error {
		verifyOnce.Do(cancelVerify)
		<-ctx.Done()
		return ctx.Err()
	}
	clientA.beforeDownload = verifyHook
	clientB.beforeDownload = verifyHook
	if claimed, err = svc.RunOne(verifyCtx, "worker-verify"); !claimed || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled verify job, claimed=%v err=%v", claimed, err)
	}
	clientA.beforeDownload = nil
	clientB.beforeDownload = nil

	ops, err = svc.Operations(base.ctx, base.actor, 100, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if ops.Jobs.Blocked != 0 {
		t.Fatalf("verify cancellation caused blocked job: %+v failures=%+v", ops.Jobs, ops.Failures)
	}
}

func TestFreshUploadAndUnissuedDeleteSkipRootListingAndShardSubdirectories(t *testing.T) {
	if os.Getenv("STUHELPER_STORAGE_TEST_DSN") == "" {
		t.Skip("PostgreSQL integration requires STUHELPER_STORAGE_TEST_DSN")
	}
	base := harnessFor(t)
	pool := bhpan.NewPool()
	t.Cleanup(pool.Close)

	now := time.Now().UTC()
	c := &clock{now: now}
	cfg := storage.Config{
		Clock:              c.Now,
		MaxObjectSize:      1 << 20,
		TemporaryDirectory: t.TempDir(),
		ParallelTransfers:  4,
		Lease:              2 * time.Minute,
		VerificationAge:    time.Minute,
		MaxAttempts:        3,
	}
	repo := &postgres.Repository{DB: base.db}
	svc, err := storage.New(repo, base.auth, pool, pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close(context.Background()) })

	clientA := newBHpanFakeClient("shard-a")
	clientB := newBHpanFakeClient("shard-b")
	expires := now.Add(2 * time.Hour)
	for idx, cl := range []*bhpanFakeClient{clientA, clientB} {
		id := fmt.Sprintf("shard-%d", idx+1)
		prov, err := pool.Provision(base.ctx, id, 1, cl, expires)
		if err != nil {
			t.Fatal(err)
		}
		prov.ID = id
		prov.OwnerDomain = id
		prov.Ownership = "platform"
		prov.State = "active"
		prov.Authorized = true
		prov.Limit = 1 << 20
		prov.Admissions = []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: expires}}
		if _, err = svc.Register(base.ctx, base.actor, "reg-"+id, prov); err != nil {
			t.Fatal(err)
		}
	}

	// A legacy flat root can already exceed the provider response limit on the first write.
	clientA.failRootList.Store(true)
	clientB.failRootList.Store(true)
	for n := 0; n < 2; n++ {
		payload := []byte(fmt.Sprintf("sharded-payload-%d", n))
		sum := sha256.Sum256(payload)
		obj, err := svc.Create(base.ctx, base.actor, fmt.Sprintf("create-%d", n), storage.CreateRequest{
			Size:       int64(len(payload)),
			SHA256:     hex.EncodeToString(sum[:]),
			Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = svc.Ingest(base.ctx, base.actor, obj.ID, fmt.Sprintf("ingest-%d", n), bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			// Verify file was stored inside a 2-hex-char shard directory under root, not directly flat in root.
			var remoteID, intent string
			if err := repo.Transaction(base.ctx, func(tx storage.Transaction) error {
				rs, e := tx.Replicas(obj.ID)
				if e == nil && len(rs) == 1 {
					remoteID = rs[0].Remote.ID
					intent = rs[0].Intent
				}
				return e
			}); err != nil {
				t.Fatal(err)
			}
			rel := strings.TrimPrefix(remoteID, clientA.root+"/")
			if strings.Count(rel, "/") != 1 {
				rel = strings.TrimPrefix(remoteID, clientB.root+"/")
			}
			if strings.Count(rel, "/") != 1 {
				t.Fatalf("expected 2-level sharded path under root for intent %s, got %s", intent, remoteID)
			}
		}
	}

	if _, err = svc.Reconcile(base.ctx, base.actor, 100, ""); err != nil {
		t.Fatal(err)
	}
	for {
		claimed, err := svc.RunOne(base.ctx, "prep-worker")
		if err != nil {
			t.Fatal(err)
		}
		if !claimed {
			break
		}
	}

	// Plan a replication (creates reserved replica with IssuedWrite=false, Remote.ID=""), then delete before worker runs.
	// Even if root List would fail (simulating >4 MiB directory), deleting an unissued reservation must succeed and free Reserved!
	payload := []byte("unissued reservation delete")
	sum := sha256.Sum256(payload)
	obj, err := svc.Create(base.ctx, base.actor, "create-del", storage.CreateRequest{
		Size:       int64(len(payload)),
		SHA256:     hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Ingest(base.ctx, base.actor, obj.ID, "ingest-del", bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Reconcile(base.ctx, base.actor, 100, ""); err != nil {
		t.Fatal(err)
	}
	// Now one instance has healthy replica (Remote.ID != ""), the other has reserved replica (IssuedWrite=false, Remote.ID="").
	clientA.failRootList.Store(true)
	clientB.failRootList.Store(true)
	if _, err = svc.Delete(base.ctx, base.actor, obj.ID, "del-obj", obj.Revision); err != nil {
		t.Fatal(err)
	}
	for {
		claimed, err := svc.RunOne(base.ctx, "del-worker")
		if err != nil && !errors.Is(err, storage.ErrStale) {
			t.Fatalf("delete replica failed when root list disabled: claimed=%v err=%v", claimed, err)
		}
		if !claimed {
			break
		}
	}
	instances, err := svc.Instances(base.ctx, base.actor, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range instances {
		if inst.Reserved != 0 {
			t.Fatalf("unissued reservation leaked capacity on %s: reserved=%d", inst.ID, inst.Reserved)
		}
	}
}

func TestRecoverFlatIntentAfterShardCached(t *testing.T) {
	h, a, b := newBHpanRecoveryHarness(t)
	data := []byte("legacy flat upload")
	hash := sha256.Sum256(data)
	o, err := h.s.Create(h.ctx, h.actor, "legacy", storage.CreateRequest{Size: int64(len(data)), SHA256: hex.EncodeToString(hash[:]), Protection: storage.Protection{Class: "public", Scope: "school-a", Public: true}})
	if err != nil {
		t.Fatal(err)
	}
	a.lostBegin.Store(true)
	b.lostBegin.Store(true)
	if _, err = h.s.Ingest(h.ctx, h.actor, o.ID, "ingest-legacy", bytes.NewReader(data)); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatal(err)
	}
	// Represent a pre-sharding upload whose response was lost. The active
	// session already knows the new shard with the same two-digit prefix.
	var flat string
	for _, cl := range []*bhpanFakeClient{a, b} {
		for key, f := range cl.files {
			if flat != "" {
				t.Fatal("expected exactly one remote upload")
			}
			f.parent = cl.root
			flat = cl.root + "/" + key
			f.documentID = flat
			f.data = data
			cl.files[key] = f
		}
	}
	h.clock.Add(6 * time.Second)
	if ok, err := h.s.RunOne(h.ctx, "recover-flat"); !ok || err != nil {
		t.Fatalf("recovery claimed=%v err=%v", ok, err)
	}
	if err = h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		copies, e := tx.Replicas(o.ID)
		if e != nil {
			return e
		}
		if flat == "" || len(copies) != 1 || copies[0].Remote.ID != flat || copies[0].State != "healthy" || copies[0].Reserved || !copies[0].Accounted {
			t.Fatalf("recovered replicas: %+v", copies)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(a.files)+len(b.files) != 1 {
		t.Fatal("recovery created another remote file")
	}
}

type multipartFenceClient struct {
	*bhpanFakeClient
	onPart             func()
	parts, completions int
}

func (c *multipartFenceClient) MultipartOptions(context.Context) (protocol.MultipartOptions, error) {
	return protocol.MultipartOptions{MinimumSize: 1, MaximumSize: 4, MaximumParts: 4}, nil
}
func (c *multipartFenceClient) BeginMultipart(ctx context.Context, parent, name string, size int64) (protocol.MultipartUpload, error) {
	upload, err := c.BeginUpload(ctx, parent, name, size)
	return protocol.MultipartUpload{DocumentID: upload.DocumentID, Revision: upload.Revision, UploadID: "fixture-upload"}, err
}
func (c *multipartFenceClient) PartGrants(_ context.Context, _ protocol.MultipartUpload, first, last int) ([]protocol.PartGrant, error) {
	return make([]protocol.PartGrant, last-first+1), nil
}
func (c *multipartFenceClient) WritePart(_ context.Context, _ protocol.PartGrant, src io.Reader, size int64) (protocol.Part, error) {
	n, err := io.Copy(io.Discard, src)
	if err != nil || n != size {
		return protocol.Part{}, storage.ErrIntegrity
	}
	c.parts++
	if c.parts == 1 {
		c.onPart()
	}
	return protocol.Part{Number: c.parts, Size: n, ETag: "fixture"}, nil
}
func (c *multipartFenceClient) CompleteMultipart(context.Context, protocol.MultipartUpload, []protocol.Part) error {
	c.completions++
	return nil
}

func TestMultipartRechecksObjectAfterPartUpload(t *testing.T) {
	h := harnessFor(t)
	pool := bhpan.NewPool()
	defer pool.Close()
	pool.SetMultipartThreshold(8)
	c := &multipartFenceClient{bhpanFakeClient: newBHpanFakeClient("multipart-fence")}
	inst, err := pool.Provision(h.ctx, "multipart-fence", 1, c, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	inst.ID = "multipart"
	inst.OwnerDomain = "test"
	inst.Ownership = "platform"
	inst.State = "active"
	inst.Authorized = true
	inst.Limit = 1024
	inst.Admissions = []storage.Admission{{Class: "public", Scope: "school-a", Plaintext: true, ExpiresAt: inst.ExpiresAt}}
	cfg := h.cfg
	cfg.TemporaryDirectory = t.TempDir()
	svc, err := storage.New(h.repo, h.auth, pool, pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close(context.Background())
	if _, err = svc.Register(h.ctx, h.actor, "register-multipart", inst); err != nil {
		t.Fatal(err)
	}
	data := []byte("0123456789abcdef")
	o := h.object(t, "fence-object", data)
	c.onPart = func() {
		if _, err := svc.Delete(h.ctx, h.actor, o.ID, "delete-after-part", o.Revision); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = svc.Ingest(h.ctx, h.actor, o.ID, "fenced-upload", bytes.NewReader(data)); !errors.Is(err, storage.ErrStale) {
		t.Fatalf("ingest: %v", err)
	}
	if c.parts == 0 || c.completions != 0 {
		t.Fatalf("parts=%d completions=%d", c.parts, c.completions)
	}
	if err = h.repo.Transaction(h.ctx, func(tx storage.Transaction) error {
		rs, err := tx.Replicas(o.ID)
		if err != nil {
			return err
		}
		if len(rs) != 1 || rs[0].Remote.ID == "" || !rs[0].IssuedWrite || rs[0].State != "cleanup" || !rs[0].Reserved || rs[0].Accounted {
			t.Fatalf("replica: %+v", rs)
		}
		i, err := tx.Instance(inst.ID)
		if err == nil && (i.Reserved != o.Size || i.Used != 0) {
			t.Fatalf("reserved=%d used=%d", i.Reserved, i.Used)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = h.db.QueryRow("SELECT state FROM storage.jobs WHERE object_id=$1 AND data->>'kind'='ingest'", o.ID).Scan(&state); err != nil || state != "done" {
		t.Fatal(state, err)
	}
}
