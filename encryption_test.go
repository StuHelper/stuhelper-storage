package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
)

// All keys here are ephemeral. The envelope makes a JSON round trip as it
// does when a restored database is opened by a new process.
func TestRestrictedEnvelopeRestoreAndAuthenticatedChunks(t *testing.T) {
	raw := make([]byte, 32)
	rand.Read(raw)
	keys := map[string][]byte{"first": raw}
	r, err := NewContentKeyring("first", keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, contentChunkBytes - 1, contentChunkBytes, contentChunkBytes + 1, 2*contentChunkBytes + 31} {
		data := make([]byte, size)
		rand.Read(data)
		sum := sha256.Sum256(data)
		o := Object{ID: newID(), Protection: Protection{Class: "restricted", Scope: "school"}, Size: int64(size), SHA256: hex.EncodeToString(sum[:])}
		if err = r.initialize(&o); err != nil {
			t.Fatal(err)
		}
		record, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		var restored Object
		if err = json.Unmarshal(record, &restored); err != nil {
			t.Fatal(err)
		}
		reopened, err := NewContentKeyring("first", keys)
		if err != nil {
			t.Fatal(err)
		}
		c, err := r.open(o)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := io.ReadAll(&encryptedReader{c, bytes.NewReader(data), nil})
		if err != nil || int64(len(sealed)) != o.storedBytes() || logicalBudget(o.Protection, o.storedBytes()) != o.Size {
			t.Fatal("cipher length", size, err)
		}
		decode := func(blob []byte, metadata Object) ([]byte, bool) {
			c, err := reopened.open(metadata)
			if err != nil {
				return nil, false
			}
			var dst bytes.Buffer
			w := &decryptedWriter{contentCipher: c, dst: &dst}
			// Driver boundaries are arbitrary, including splits inside a tag.
			for len(blob) > 0 {
				n := min(50789, len(blob))
				if _, err = w.Write(blob[:n]); err != nil {
					return nil, false
				}
				blob = blob[n:]
			}
			return dst.Bytes(), w.left == 0 && w.filled == 0
		}
		got, ok := decode(sealed, restored)
		if !ok || !bytes.Equal(got, data) {
			t.Fatal("restore mismatch", size)
		}
		tampered := bytes.Clone(sealed)
		tampered[len(tampered)-1] ^= 1
		if _, ok = decode(tampered, restored); ok {
			t.Fatal("accepted corruption")
		}
		if _, ok = decode(sealed[:len(sealed)-1], restored); ok {
			t.Fatal("accepted truncation")
		}
		if _, ok = decode(append(bytes.Clone(sealed), 0), restored); ok {
			t.Fatal("accepted trailing bytes")
		}
		if size > 2*contentChunkBytes {
			frame := contentChunkBytes + contentTagBytes
			swapped := bytes.Clone(sealed)
			copy(swapped[:frame], sealed[frame:2*frame])
			copy(swapped[frame:2*frame], sealed[:frame])
			if _, ok = decode(swapped, restored); ok {
				t.Fatal("accepted reordered chunks")
			}
		}
		restored.ID = newID()
		if _, ok = decode(sealed, restored); ok {
			t.Fatal("accepted cross-object envelope")
		}
	}
	other := make([]byte, 32)
	rand.Read(other)
	wrong, err := NewContentKeyring("first", map[string][]byte{"first": other})
	if err != nil {
		t.Fatal(err)
	}
	o := Object{ID: newID(), Size: 9, Protection: Protection{Class: "restricted", Scope: "school"}}
	if err = r.initialize(&o); err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.open(o); err != ErrRestrictedUnavailable {
		t.Fatal("wrong wrapping key should stop reads without invalidating replicas")
	}
}
