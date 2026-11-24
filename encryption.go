package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	contentChunkBytes = 1 << 20
	contentTagBytes   = 16
	envelopeFormat    = 1
)

// ContentEnvelope is stored with the immutable object in the private database.
// Storage providers receive only the authenticated chunks. The database contains
// a wrapped data key and the nonce prefix, never an unwrapped key.
type ContentEnvelope struct {
	Format  int    `json:"format"`
	KeyID   string `json:"key_id"`
	Wrapped []byte `json:"wrapped"`
	Prefix  []byte `json:"prefix"`
}

type ContentKeyring struct {
	active string
	keys   map[string]cipher.AEAD
}

// NewContentKeyring takes the active wrapping key and the retained read keys.
// The host loads key material only from its private, versioned keyring.
func NewContentKeyring(active string, keys map[string][]byte) (*ContentKeyring, error) {
	if !validID(active) || len(keys) == 0 || len(keys) > 32 {
		return nil, ErrInput
	}
	r := &ContentKeyring{active: active, keys: make(map[string]cipher.AEAD, len(keys))}
	for id, raw := range keys {
		if !validID(id) || len(raw) != 32 {
			return nil, ErrInput
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, ErrInput
		}
		r.keys[id], err = cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			return nil, ErrUnavailable
		}
	}
	if r.keys[active] == nil {
		return nil, ErrInput
	}
	return r, nil
}

func (o Object) contentContext() string {
	return requestHash([]any{"stuhelper-storage-content", envelopeFormat, o.ID, o.Protection.Class, o.Protection.Scope, o.Size, o.SHA256, contentChunkBytes})
}

func storedSize(p Protection, size int64) int64 {
	if p.Class != "restricted" || size <= 0 {
		return size
	}
	return size + ((size-1)/contentChunkBytes+1)*contentTagBytes
}

func logicalBudget(p Protection, physical int64) int64 {
	if p.Class != "restricted" {
		return physical
	}
	const frame = contentChunkBytes + contentTagBytes
	return physical/frame*contentChunkBytes + max(0, physical%frame-contentTagBytes)
}

func (o Object) storedBytes() int64 { return storedSize(o.Protection, o.Size) }

// The rollback slot keeps its read keys installed while new restricted writes
// are paused. Already accepted replicas remain verifiable and repairable.
func (s *Service) initializeVersion(o *Object) error {
	if o.Protection.Class == "restricted" && !s.cfg.RestrictedWrites {
		return ErrRestrictedUnavailable
	}
	return s.cfg.ContentKeys.initialize(o)
}

func (r *ContentKeyring) initialize(o *Object) error {
	if o.Protection.Class != "restricted" {
		return nil
	}
	if r == nil {
		return ErrRestrictedUnavailable
	}
	var dek [32]byte
	rand.Read(dek[:])
	defer clear(dek[:])
	e := &ContentEnvelope{Format: envelopeFormat, KeyID: r.active, Prefix: make([]byte, 8)}
	rand.Read(e.Prefix)
	e.Wrapped = r.keys[r.active].Seal(nil, nil, dek[:], e.wrapContext(*o))
	o.Envelope = e
	return nil
}

func (e *ContentEnvelope) wrapContext(o Object) []byte {
	return []byte(requestHash([]any{"stuhelper-storage-wrap", o.contentContext(), e.KeyID, e.Prefix}))
}

func (r *ContentKeyring) unwrap(o Object) ([]byte, error) {
	e := o.Envelope
	if r == nil || e == nil || e.Format != envelopeFormat || len(e.Prefix) != 8 || len(e.Wrapped) != 60 || r.keys[e.KeyID] == nil {
		return nil, ErrRestrictedUnavailable
	}
	raw, err := r.keys[e.KeyID].Open(nil, nil, e.Wrapped, e.wrapContext(o))
	// A keyring/metadata failure applies to every replica. Do not mark good
	// ciphertext corrupt or delete it in response to a wrong/unavailable KEK.
	if err != nil || len(raw) != 32 {
		return nil, ErrRestrictedUnavailable
	}
	return raw, nil
}

type contentCipher struct {
	aead    cipher.AEAD
	prefix  [8]byte
	context []byte
	index   uint32
	left    int64
	block   []byte
}

func (r *ContentKeyring) open(o Object) (*contentCipher, error) {
	raw, err := r.unwrap(o)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, ErrRestrictedUnavailable
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrRestrictedUnavailable
	}
	c := &contentCipher{aead: a, context: []byte(o.contentContext()), left: o.Size, block: make([]byte, min(o.Size, int64(contentChunkBytes))+contentTagBytes)}
	copy(c.prefix[:], o.Envelope.Prefix)
	return c, nil
}

func (c *contentCipher) parameters() ([]byte, []byte) {
	var nonce [12]byte
	copy(nonce[:8], c.prefix[:])
	binary.BigEndian.PutUint32(nonce[8:], c.index)
	return nonce[:], binary.BigEndian.AppendUint32(c.context, c.index)
}

type encryptedReader struct {
	*contentCipher
	src     io.Reader
	pending []byte
}

func (r *encryptedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if r.left == 0 {
			return 0, io.EOF
		}
		n := min(r.left, int64(contentChunkBytes))
		cleartext := r.block[:n]
		if _, err := io.ReadFull(r.src, cleartext); err != nil {
			return 0, ErrIntegrity
		}
		nonce, aad := r.parameters()
		r.pending = r.aead.Seal(r.block[:0], nonce, cleartext, aad)
		r.index++
		r.left -= n
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// Drivers push arbitrarily fragmented reads. Only complete, authenticated
// chunks reach the private staging file, which is served after full checksum
// verification and a second authorization check.
type decryptedWriter struct {
	*contentCipher
	dst    io.Writer
	filled int
}

func (w *decryptedWriter) Write(p []byte) (int, error) {
	accepted := 0
	for len(p) > 0 {
		if w.left == 0 {
			return accepted, ErrIntegrity
		}
		plain := min(w.left, int64(contentChunkBytes))
		length := int(plain) + contentTagBytes
		n := copy(w.block[w.filled:length], p)
		w.filled += n
		accepted += n
		p = p[n:]
		if w.filled == length {
			nonce, aad := w.parameters()
			decoded, err := w.aead.Open(w.block[:0], nonce, w.block[:length], aad)
			if err != nil {
				return accepted, ErrIntegrity
			}
			n, err := w.dst.Write(decoded)
			if err != nil {
				return accepted, err
			}
			if n != len(decoded) {
				return accepted, io.ErrShortWrite
			}
			w.left -= plain
			w.index++
			w.filled = 0
		}
	}
	return accepted, nil
}

// RewrapContentKeys upgrades a bounded page in a transaction. Re-running a
// page after a lost response is safe. Old keys stay available until every
// retained object and its backup can be restored.
func (s *Service) RewrapContentKeys(ctx context.Context, p Principal, after string, limit int) (next string, changed int, err error) {
	if limit < 1 || limit > 100 || (after != "" && !validID(after)) {
		return "", 0, ErrInput
	}
	if err = s.authorize(ctx, p, "storage.keys.rotate", "", Protection{}); err != nil {
		return "", 0, err
	}
	r := s.cfg.ContentKeys
	if r == nil {
		return "", 0, ErrRestrictedUnavailable
	}
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		rows, err := tx.Objects(limit, after)
		if err != nil {
			return err
		}
		for _, snapshot := range rows {
			if snapshot.Protection.Class != "restricted" || snapshot.State == "deleted" {
				continue
			}
			o, err := tx.Object(snapshot.ID)
			if err != nil {
				return err
			}
			if o.Protection.Class != "restricted" || o.State == "deleted" {
				continue
			}
			raw, err := r.unwrap(o)
			if err != nil {
				return err
			}
			if o.Envelope.KeyID != r.active {
				o.Envelope.KeyID = r.active
				o.Envelope.Wrapped = r.keys[r.active].Seal(nil, nil, raw, o.Envelope.wrapContext(o))
				clear(raw)
				if err = tx.SaveObject(o); err != nil {
					return err
				}
				if err = s.emitScoped(ctx, tx, p, "storage.content.key_rewrapped", o.ID, o.Revision, "success", o.Protection.Scope); err != nil {
					return err
				}
				changed++
			} else {
				clear(raw)
			}
		}
		if len(rows) == limit {
			next = rows[len(rows)-1].ID
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return next, changed, nil
}

var ErrRestrictedUnavailable = errors.New("storage_restricted_encryption_unavailable")
