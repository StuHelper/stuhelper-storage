package storage_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	s "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/storagetest"
)

func TestRestrictedCiphertextPerVersionAndRotation(t *testing.T) {
	first := make([]byte, 32)
	second := make([]byte, 32)
	rand.Read(first)
	rand.Read(second)
	keymap := map[string][]byte{"v1": first, "v2": second}
	keys, err := s.NewContentKeyring("v1", keymap)
	if err != nil {
		t.Fatal(err)
	}
	h := harnessFor(t, func(c *s.Config) { c.RestrictedWrites = true; c.ContentKeys = keys; c.MaxObjectSize = 2 << 20 })
	for _, id := range []string{"one", "two"} {
		item := registerContributor(t, h, id, h.actor, 8<<20)
		if _, err = storagetest.Trust(h.ctx, h.s, h.actor, item, "school-a", []string{"restricted"}); err != nil {
			t.Fatal(err)
		}
	}
	data := make([]byte, 1<<20+23)
	rand.Read(data)
	digest := sha256.Sum256(data)
	p := s.Protection{Class: "restricted", Scope: "school-a"}
	req := s.CreateRequest{Deduplicate: true, Size: int64(len(data)), Protection: p, ReserveFor: &p, SHA256: hex.EncodeToString(digest[:])}
	var handles []string
	for _, key := range []string{"first-version", "second-version"} {
		req.ClientKey = key
		st, err := h.s.Create(h.ctx, h.actor, key, req)
		if err != nil {
			t.Fatal(err)
		}
		handles = append(handles, st.ID)
		h.ingest(t, st.ID, data)
		h.run(t)
		if err = h.s.OpenDownload(h.ctx, h.actor, st.ID, func(v s.VerifiedContent) error {
			if v.Size != int64(len(data)) {
				t.Fatal("wrong logical length")
			}
			if _, err := v.Body.Seek(1<<20-9, io.SeekStart); err != nil {
				return err
			}
			part := make([]byte, 28)
			if _, err := io.ReadFull(v.Body, part); err != nil {
				return err
			}
			if !bytes.Equal(part, data[1<<20-9:1<<20+19]) {
				t.Fatal("incorrect cross-chunk range")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A public or quarantine upload cannot become a restricted immutable
	// version after its bytes have already reached a plaintext replica.
	public := s.Protection{Class: "public", Public: true, Scope: p.Scope}
	bad := req
	bad.ClientKey = "mixed-protection"
	bad.Protection = public
	if _, e := h.s.Create(h.ctx, h.actor, "mixed-protection", bad); !errors.Is(e, s.ErrInput) {
		t.Fatal("accepted a plaintext first stage for restricted content", e)
	}
	before, e := h.s.Status(h.ctx, h.actor, handles[0])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.s.ChangeProtection(h.ctx, h.actor, handles[0], "publish-restricted-plain", before.Revision, public); !errors.Is(e, s.ErrConflict) {
		t.Fatal("mutated an encrypted version into public plaintext", e)
	}
	after, e := h.s.Status(h.ctx, h.actor, handles[0])
	if e != nil || before != after {
		t.Fatal("denied mutation changed the restricted version", e)
	}
	physical := len(data) + 2*16
	seen := map[[32]byte]int{}
	for _, objects := range h.provider.files {
		if len(objects) != 2 {
			t.Fatal("versions were deduplicated")
		}
		for _, replica := range objects {
			if len(replica) != physical || bytes.Contains(replica, data[:256]) {
				t.Fatal("invalid stored bytes")
			}
			seen[sha256.Sum256(replica)]++
		}
	}
	if len(seen) != 2 {
		t.Fatal("each version needs independent ciphertext")
	}
	for _, n := range seen {
		if n != 2 {
			t.Fatal("replicas did not match")
		}
	}
	items, err := h.s.Instances(h.ctx, h.actor, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range items {
		if i.Used != int64(physical*2) || i.Reserved != 0 {
			t.Fatal("incorrect physical accounting")
		}
	}
	cfg := h.cfg
	cfg.TemporaryDirectory = t.TempDir()
	cfg.ContentKeys, err = s.NewContentKeyring("v2", keymap)
	if err != nil {
		t.Fatal(err)
	}
	rotator, err := s.New(h.repo, h.auth, h.provider, h.provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rotator.Close(h.ctx)
	cursor, n, err := rotator.RewrapContentKeys(h.ctx, h.actor, "", 1)
	if err != nil || cursor == "" || n != 1 {
		t.Fatal("first rotation page", err, n)
	}
	_, n, err = rotator.RewrapContentKeys(h.ctx, h.actor, "", 1)
	if err != nil || n != 0 {
		t.Fatal("lost rotation response", err, n)
	}
	_, n, err = rotator.RewrapContentKeys(h.ctx, h.actor, cursor, 10)
	if err != nil || n != 1 {
		t.Fatal("resumed rotation", err, n)
	}
	cfg.ContentKeys, err = s.NewContentKeyring("v2", map[string][]byte{"v2": second})
	if err != nil {
		t.Fatal(err)
	}
	cfg.TemporaryDirectory = t.TempDir()
	cfg.RestrictedWrites = false
	reopened, err := s.New(h.repo, h.auth, h.provider, h.provider, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close(h.ctx)
	for _, id := range handles {
		var out bytes.Buffer
		if err = reopened.Download(h.ctx, h.actor, id, &out); err != nil || !bytes.Equal(data, out.Bytes()) {
			t.Fatal("read after retiring previous key", err)
		}
	}
	req.ClientKey = "paused-version"
	if _, err = reopened.Create(h.ctx, h.actor, "paused-version", req); !errors.Is(err, s.ErrRestrictedUnavailable) {
		t.Fatal("read-only rollback admitted a new restricted version", err)
	}
	req.ReuseFrom = handles[0]
	req.ClientKey = "bad-reuse"
	if _, err = reopened.Create(h.ctx, h.actor, "bad-reuse", req); !errors.Is(err, s.ErrInput) {
		t.Fatal("accepted cross-version reuse", err)
	}
	pubReq := s.CreateRequest{Deduplicate: true, ClientKey: "public-version", Size: int64(len(data)), SHA256: req.SHA256, Protection: public}
	pub, e := h.s.Create(h.ctx, h.actor, "public-version", pubReq)
	if e != nil {
		t.Fatal(e)
	}
	pub = h.ingest(t, pub.ID, data)
	writes := h.provider.writes
	if _, e = h.s.ChangeProtection(h.ctx, h.actor, pub.ID, "classify-after-upload", pub.Revision, p); !errors.Is(e, s.ErrConflict) {
		t.Fatal("accepted a restricted classification after plaintext upload", e)
	}
	unchanged, e := h.s.Status(h.ctx, h.actor, pub.ID)
	if e != nil || unchanged != pub || writes != h.provider.writes {
		t.Fatal("denied reclassification changed storage", e)
	}

}
