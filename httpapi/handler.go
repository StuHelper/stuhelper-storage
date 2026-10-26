// Package httpapi exposes the storage contract. Authentication is supplied by
// the composition root; the service independently authorizes every operation.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/sdk"
)

type Authenticator interface {
	Authenticate(*http.Request) (storage.Principal, error)
}
type handler struct {
	s     *storage.Service
	auth  Authenticator
	limit int64
}
type endpoint func(http.ResponseWriter, *http.Request, storage.Principal) (any, error)

func New(s *storage.Service, auth Authenticator, maxUpload int64) (http.Handler, error) {
	if s == nil || maxUpload < 1 || maxUpload > 1<<30 {
		return nil, storage.ErrInput
	}
	h := &handler{s, auth, maxUpload}
	mux := http.NewServeMux()
	h.mount(mux, "GET /api/v1/storage/instances", false, h.instances)
	h.mount(mux, "POST /api/v1/storage/instances", false, h.register)
	h.mount(mux, "PUT /api/v1/storage/instances/{id}", false, h.update)
	h.mount(mux, "POST /api/v1/storage/objects", false, h.create)
	h.mount(mux, "GET /api/v1/storage/objects/{id}", false, func(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
		return h.s.Status(r.Context(), p, r.PathValue("id"))
	})
	h.mount(mux, "DELETE /api/v1/storage/objects/{id}", false, h.remove)
	h.mount(mux, "PUT /api/v1/storage/objects/{id}/content", true, h.upload)
	h.mount(mux, "GET /api/v1/storage/objects/{id}/content", false, h.download)
	h.mount(mux, "POST /api/v1/storage/objects/{id}/references", false, h.reference)
	h.mount(mux, "DELETE /api/v1/storage/objects/{id}/references", false, h.reference)
	h.mount(mux, "PUT /api/v1/storage/objects/{id}/protection", false, h.protection)
	h.mount(mux, "POST /api/v1/storage/maintenance", false, h.maintenance)
	return mux, nil
}
func (h *handler) mount(mux *http.ServeMux, path string, upload bool, run endpoint) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if h.auth == nil {
			problem(w, 503, "identity_unavailable")
			return
		}
		p, err := h.auth.Authenticate(r)
		if err != nil || !p.Valid() {
			if errors.Is(err, storage.ErrUnavailable) {
				problem(w, 503, "identity_unavailable")
			} else {
				problem(w, 401, "authentication_required")
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		controller := http.NewResponseController(w)
		deadline, _ := ctx.Deadline()
		_ = controller.SetReadDeadline(deadline)
		_ = controller.SetWriteDeadline(deadline)
		stopIO := context.AfterFunc(ctx, func() {
			_ = controller.SetReadDeadline(time.Now())
			_ = controller.SetWriteDeadline(time.Now())
		})
		defer stopIO()
		r = r.WithContext(ctx)
		limit := int64(1 << 20)
		if upload {
			limit = h.limit
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		out, err := run(w, r, p)
		if err != nil {
			respondError(w, err)
			return
		}
		if out != nil {
			writeJSON(w, 200, out)
		}
	})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Del("Content-Disposition")
	writeJSON(w, status, map[string]string{"code": code})
}
func respondError(w http.ResponseWriter, err error) {
	status, code := 503, storage.ErrUnavailable.Error()
	for _, entry := range []struct {
		err    error
		status int
	}{{storage.ErrInput, 400}, {storage.ErrDenied, 403}, {storage.ErrNotFound, 404}, {storage.ErrConflict, 409}, {storage.ErrStale, 409}, {storage.ErrCapacity, 503}, {storage.ErrIntegrity, 409}, {storage.ErrUnknown, 503}} {
		if errors.Is(err, entry.err) {
			status, code = entry.status, entry.err.Error()
			break
		}
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status, code = 413, "storage_upload_too_large"
	}
	problem(w, status, code)
}
func decode[T any](r *http.Request) (T, error) {
	var out T
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		return out, storage.ErrInput
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&out); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			return out, err
		}
		return out, storage.ErrInput
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return out, storage.ErrInput
	}
	return out, nil
}
func convert[A, B any](value A) (B, error) {
	var out B
	b, err := json.Marshal(value)
	if err != nil {
		return out, storage.ErrInput
	}
	if json.Unmarshal(b, &out) != nil {
		return out, storage.ErrInput
	}
	return out, nil
}
func (h *handler) instances(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return nil, storage.ErrInput
		}
	}
	items, err := h.s.Instances(r.Context(), p, limit, r.URL.Query().Get("after"))
	if err != nil {
		return nil, err
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].ID
	}
	return map[string]any{"items": items, "next_cursor": next}, nil
}
func (h *handler) register(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.InstanceInput](r)
	if err != nil {
		return nil, err
	}
	v, err := convert[sdk.InstanceInput, storage.Instance](input)
	if err != nil {
		return nil, err
	}
	return h.s.Register(r.Context(), p, r.Header.Get("Idempotency-Key"), v)
}
func (h *handler) update(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.InstanceInput](r)
	if err != nil {
		return nil, err
	}
	v, err := convert[sdk.InstanceInput, storage.Instance](input)
	if err != nil {
		return nil, err
	}
	if v.ID != r.PathValue("id") {
		return nil, storage.ErrInput
	}
	return h.s.UpdateInstance(r.Context(), p, r.Header.Get("Idempotency-Key"), v)
}
func (h *handler) create(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.CreateObject](r)
	if err != nil {
		return nil, err
	}
	v, err := convert[sdk.CreateObject, storage.CreateRequest](input)
	if err != nil {
		return nil, err
	}
	return h.s.Create(r.Context(), p, r.Header.Get("Idempotency-Key"), v)
}
func (h *handler) remove(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.Revision](r)
	if err != nil {
		return nil, err
	}
	return h.s.Delete(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), input.Revision)
}
func (h *handler) upload(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/octet-stream" {
		return nil, storage.ErrInput
	}
	if r.ContentLength > h.limit {
		return nil, &http.MaxBytesError{Limit: h.limit}
	}
	return h.s.Ingest(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), r.Body)
}

type trackingWriter struct {
	http.ResponseWriter
	started bool
}

func (w *trackingWriter) Write(b []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(b)
}
func (h *handler) download(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	status, err := h.s.Status(r.Context(), p, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(status.Size, 10))
	w.Header().Set("Content-Disposition", "attachment")
	writer := &trackingWriter{ResponseWriter: w}
	err = h.s.Download(r.Context(), p, status.ID, writer)
	if err != nil && writer.started {
		panic(http.ErrAbortHandler)
	}
	return nil, err
}
func (h *handler) reference(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.Reference](r)
	if err != nil {
		return nil, err
	}
	return h.s.Reference(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), storage.Reference{Module: input.Module, ID: input.Id}, r.Method == http.MethodPost)
}
func (h *handler) protection(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.ProtectionChange](r)
	if err != nil {
		return nil, err
	}
	v, err := convert[sdk.Protection, storage.Protection](input.Protection)
	if err != nil {
		return nil, err
	}
	return h.s.ChangeProtection(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), input.Revision, v)
}
func (h *handler) maintenance(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.Maintenance](r)
	if err != nil {
		return nil, err
	}
	return h.s.Reconcile(r.Context(), p, input.Limit, input.After)
}
