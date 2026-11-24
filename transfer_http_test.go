package storage_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/httpapi"
)

func TestStreamingHashRangeAndETagDownload(t *testing.T) {
	h := harnessFor(t)
	for n := 1; n <= 3; n++ {
		h.instance(t, fmt.Sprintf("i%d", n), fmt.Sprintf("owner-%d", n), 1<<20)
	}
	data := bytes.Repeat([]byte("abcdefghijklmnopqrstuvwxyz012345"), 1024)
	sum := sha256.Sum256(data)
	expectedETag := `"` + hex.EncodeToString(sum[:]) + `"`

	obj := h.object(t, "range-obj", data)
	h.ingest(t, obj.ID, data)
	h.reconcile(t)
	h.run(t)
	h.run(t)

	shared := sharedCreate(t, h, "range-shared", sharedRequest(data))
	h.ingest(t, shared.ID, data)
	h.reconcile(t)
	drainContent(t, h)

	if err := h.s.OpenDownload(h.ctx, h.actor, obj.ID, func(c storage.VerifiedContent) error {
		if c.Size != int64(len(data)) || `"`+c.SHA256+`"` != expectedETag {
			t.Fatalf("unexpected verified metadata: %+v", c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	handler, err := httpapi.New(h.s, testAuthentication{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	requestDownload := func(id string, headers map[string]string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest("GET", server.URL+"/api/v1/storage/objects/"+id+"/content", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer synthetic-test-token")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, body
	}

	for _, id := range []string{obj.ID, shared.ID} {
		resp, body := requestDownload(id, nil)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(body, data) {
			t.Fatalf("%s full download status=%d len=%d", id, resp.StatusCode, len(body))
		}
		if resp.Header.Get("ETag") != expectedETag || resp.Header.Get("Accept-Ranges") != "bytes" || resp.Header.Get("Content-Disposition") != "attachment" {
			t.Fatalf("%s unexpected headers: %+v", id, resp.Header)
		}

		resp304, body304 := requestDownload(id, map[string]string{"If-None-Match": expectedETag})
		if resp304.StatusCode != http.StatusNotModified || len(body304) != 0 || resp304.Header.Get("ETag") != expectedETag {
			t.Fatalf("%s conditional 304 failed: status=%d len=%d", id, resp304.StatusCode, len(body304))
		}

		resp206, body206 := requestDownload(id, map[string]string{"Range": "bytes=10-41", "If-Range": expectedETag})
		if resp206.StatusCode != http.StatusPartialContent || !bytes.Equal(body206, data[10:42]) {
			t.Fatalf("%s partial 206 failed: status=%d body=%q", id, resp206.StatusCode, body206)
		}
		wantRange := fmt.Sprintf("bytes 10-41/%d", len(data))
		if resp206.Header.Get("Content-Range") != wantRange || resp206.Header.Get("ETag") != expectedETag {
			t.Fatalf("%s bad range headers: %+v", id, resp206.Header)
		}

		resp416, _ := requestDownload(id, map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", len(data)+10, len(data)+20)})
		if resp416.StatusCode != http.StatusRequestedRangeNotSatisfiable {
			t.Fatalf("%s expected 416, got %d", id, resp416.StatusCode)
		}
	}

	// Denied requests with matching If-None-Match must still return 403, never 304.
	h.auth.denied.Store(true)
	deniedResp, _ := requestDownload(obj.ID, map[string]string{"If-None-Match": expectedETag})
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied conditional request leaked status %d", deniedResp.StatusCode)
	}
	h.auth.denied.Store(false)

	// Chunked upload exceeding maxUpload returns 413 on non-deduplicated object too.
	exactMax := bytes.Repeat([]byte("a"), 256)
	smallHandler, err := httpapi.New(h.s, testAuthentication{}, int64(len(exactMax)))
	if err != nil {
		t.Fatal(err)
	}
	smallServer := httptest.NewServer(smallHandler)
	defer smallServer.Close()
	exactObj := h.object(t, "exact-max", exactMax)
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(bytes.Repeat([]byte("a"), len(exactMax)+1))
		_ = pw.Close()
	}()
	upReq, _ := http.NewRequest("PUT", smallServer.URL+"/api/v1/storage/objects/"+exactObj.ID+"/content", pr)
	upReq.Header.Set("Authorization", "Bearer synthetic-test-token")
	upReq.Header.Set("Content-Type", "application/octet-stream")
	upReq.Header.Set("Idempotency-Key", "chunked-overflow")
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		t.Fatal(err)
	}
	upResp.Body.Close()
	if upResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for chunked upload overflow, got %d", upResp.StatusCode)
	}

	// Corrupt remote content with Range request must never leak partial bytes or ETag.
	h.provider.mu.Lock()
	for _, files := range h.provider.files {
		for _, content := range files {
			content[len(content)-1] ^= 0xff
		}
	}
	h.provider.mu.Unlock()
	corruptResp, corruptBody := requestDownload(obj.ID, map[string]string{"Range": "bytes=0-15"})
	if corruptResp.StatusCode != http.StatusServiceUnavailable || corruptResp.Header.Get("ETag") != "" || bytes.Contains(corruptBody, data[:16]) {
		t.Fatalf("corrupt range download leaked status=%d etag=%q", corruptResp.StatusCode, corruptResp.Header.Get("ETag"))
	}
}
