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
	h.mount(mux, "GET /api/v1/storage/operations", false, h.operations)
	h.mount(mux, "GET /api/v1/storage/contribution-admission-policy", false, h.admissionPolicy)
	h.mount(mux, "PUT /api/v1/storage/contribution-admission-policy", false, h.replaceAdmissionPolicy)
	h.mount(mux, "GET /api/v1/storage/contributions", false, func(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
		n := 25
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var e error
			n, e = strconv.Atoi(raw)
			if e != nil {
				return nil, storage.ErrInput
			}
		}
		return s.ListContributionCandidates(r.Context(), p, r.URL.Query().Get("owner_domain"), n, r.URL.Query().Get("after"))
	})
	h.mount(mux, "GET /api/v1/storage/contributions/community/summary", false, func(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
		return h.s.SummarizeContributions(r.Context(), p)
	})
	h.mount(mux, "GET /api/v1/storage/contributions/{id}", false, func(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
		return h.s.InspectContribution(r.Context(), p, r.PathValue("id"), r.URL.Query().Get("owner_domain"))
	})
	h.mount(mux, "PUT /api/v1/storage/contributions/{id}", false, func(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
		input, err := decode[sdk.ContributionControl](r)
		if err != nil {
			return nil, err
		}
		control, err := convert[sdk.ContributionControl, storage.ContributionControl](input)
		if err != nil {
			return nil, err
		}
		return h.s.ApplyContribution(r.Context(), p, r.PathValue("id"), control)
	})
	h.mount(mux, "POST /api/v1/storage/operations/instances/{id}/commands", false, h.commandInstance)
	h.mount(mux, "POST /api/v1/storage/operations/objects/{object_id}/jobs/{job_id}/retry", false, h.retryJob)
	h.mount(mux, "POST /api/v1/storage/operations/objects/{object_id}/replicas/{replica_id}/writeoff", false, h.writeOffReplica)
	h.mount(mux, "GET /api/v1/storage/instances/{id}/trust-consent", false, func(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
		return h.s.OwnTrustConsent(r.Context(), p, r.PathValue("id"))
	})
	h.mount(mux, "PUT /api/v1/storage/instances/{id}/trust-consent", false, func(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
		input, err := decode[storage.TrustConsentRequest](r)
		if err != nil {
			return nil, err
		}
		return h.s.SetOwnTrustConsent(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), input)
	})
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
	h.mount(mux, "GET /api/v1/storage/objects/{id}/review-content", false, h.reviewDownload)
	h.mount(mux, "POST /api/v1/storage/objects/{id}/references", false, h.reference)
	h.mount(mux, "DELETE /api/v1/storage/objects/{id}/references", false, h.reference)
	h.mount(mux, "PUT /api/v1/storage/objects/{id}/protection", false, h.protection)
	h.mount(mux, "POST /api/v1/storage/maintenance", false, h.maintenance)
	return mux, nil
}

func (h *handler) admissionPolicy(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	return h.s.ContributionAdmissionPolicy(r.Context(), p)
}

func (h *handler) replaceAdmissionPolicy(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	value, err := decode[sdk.ContributionAdmissionPolicy](r)
	if err != nil {
		return nil, err
	}
	policy, err := convert[sdk.ContributionAdmissionPolicy, storage.ContributionAdmissionPolicy](value)
	if err != nil {
		return nil, err
	}
	return h.s.ReplaceContributionAdmissionPolicy(r.Context(), p, r.Header.Get("Idempotency-Key"), policy)
}

func (h *handler) commandInstance(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.InstanceCommand](r)
	if err != nil {
		return nil, err
	}
	command, err := convert[sdk.InstanceCommand, storage.InstanceCommand](input)
	if err != nil {
		return nil, err
	}
	return h.s.CommandInstance(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), command)
}
func (h *handler) retryJob(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.RetryJob](r)
	if err != nil {
		return nil, err
	}
	return h.s.RetryJob(r.Context(), p, r.PathValue("object_id"), r.PathValue("job_id"), r.Header.Get("Idempotency-Key"), input.Generation)
}
func (h *handler) writeOffReplica(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	input, err := decode[sdk.ReplicaWriteOff](r)
	if err != nil {
		return nil, err
	}
	req, err := convert[sdk.ReplicaWriteOff, storage.ReplicaWriteOff](input)
	if err != nil {
		return nil, err
	}
	return h.s.WriteOffUnknownReplica(r.Context(), p, r.PathValue("object_id"), r.PathValue("replica_id"), r.Header.Get("Idempotency-Key"), req)
}
func (h *handler) operations(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return nil, storage.ErrInput
		}
	}
	q := r.URL.Query()
	return h.s.QueryOperations(r.Context(), p, storage.OperationsQuery{
		Limit:         limit,
		After:         q.Get("after"),
		FailuresAfter: q.Get("failures_after"),
		ObjectFilter:  q.Get("object_filter"),
		FailureState:  q.Get("failure_state"),
		FailureKind:   q.Get("failure_kind"),
		ErrorCode:     q.Get("error_code"),
	})
}

type routeOptions struct {
	auth            Authenticator
	public          bool
	timeout         time.Duration
	maxBodyBytes    int64
	unavailableCode string

	successStatus func(*http.Request) int
}

func mountEndpoint(mux *http.ServeMux, path string, opts routeOptions, run endpoint) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), opts.timeout)
		defer cancel()
		if tp := r.Header.Get("Traceparent"); tp != "" {
			ctx = storage.WithTraceParent(ctx, tp)
		}
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
		r.Body = http.MaxBytesReader(w, r.Body, opts.maxBodyBytes)
		var p storage.Principal
		if !opts.public {
			if opts.auth == nil {
				problem(w, 503, opts.unavailableCode)
				return
			}
			var err error
			p, err = opts.auth.Authenticate(r)
			if err != nil || !p.Valid() {
				if errors.Is(err, storage.ErrUnavailable) {
					problem(w, 503, opts.unavailableCode)
				} else {
					problem(w, 401, "authentication_required")
				}
				return
			}
		}
		if len(r.Header.Values("Idempotency-Key")) > 1 {
			respondError(w, storage.ErrInput)
			return
		}
		out, err := run(w, r, p)
		if err != nil {
			respondError(w, err)
			return
		}
		if out != nil {
			status := 200
			if opts.successStatus != nil {
				status = opts.successStatus(r)
			}
			writeJSON(w, status, out)
		}
	})
}

func (h *handler) mount(mux *http.ServeMux, path string, upload bool, run endpoint) {
	limit := int64(1 << 20)
	if upload {
		limit = h.limit
	}
	mountEndpoint(mux, path, routeOptions{
		auth:            h.auth,
		timeout:         5 * time.Minute,
		maxBodyBytes:    limit,
		unavailableCode: "identity_unavailable",
	}, run)
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
	}{{storage.ErrInput, 400}, {storage.ErrChallenge, 403}, {storage.ErrDenied, 403}, {storage.ErrNotFound, 404},
		{storage.ErrConflict, 409}, {storage.ErrStale, 409}, {storage.ErrContributionLimitExceeded, 409}, {storage.ErrContributionCapacityUnavailable, 409},
		{storage.ErrReplicaSpace, 503}, {storage.ErrReplicaShortage, 503}, {storage.ErrRestrictedUnavailable, 503}, {storage.ErrCapacity, 503}, {storage.ErrIntegrity, 409}, {storage.ErrUnknown, 503}} {
		if errors.Is(err, entry.err) {
			status, code = entry.status, entry.err.Error()
			break
		}
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status, code = 413, "storage_upload_too_large"
	}
	var retryAfter storage.RetryAfterError
	if errors.As(err, &retryAfter) && retryAfter.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter.RetryAfterSeconds))
		w.Header().Del("Content-Disposition")
		writeJSON(w, status, map[string]any{"code": code, "retry_after_seconds": retryAfter.RetryAfterSeconds})
		return
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

type instanceResponse struct {
	storage.Instance
	ProviderFree *int64 `json:"provider_free,omitempty"`
}

func projectInstance(i storage.Instance) instanceResponse {
	result := instanceResponse{Instance: i}
	if i.Ownership != "contributor" {
		result.ProviderFree = &i.ProviderFree
	}
	return result
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
	instances := make([]instanceResponse, 0, len(items))
	for _, i := range items {
		instances = append(instances, projectInstance(i))
	}
	return map[string]any{"items": instances, "next_cursor": next}, nil
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
	result, err := h.s.Register(r.Context(), p, r.Header.Get("Idempotency-Key"), v)
	return projectInstance(result), err
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
	result, err := h.s.UpdateInstance(r.Context(), p, r.Header.Get("Idempotency-Key"), v)
	return projectInstance(result), err
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

func (w *trackingWriter) WriteHeader(statusCode int) {
	w.started = true
	w.ResponseWriter.WriteHeader(statusCode)
}
func (w *trackingWriter) Write(b []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(b)
}
func (h *handler) download(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	writer := &trackingWriter{ResponseWriter: w}
	err := h.s.OpenDownload(r.Context(), p, r.PathValue("id"), func(content storage.VerifiedContent) error {
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("Content-Disposition", "attachment")
		writer.Header().Set("ETag", `"`+content.SHA256+`"`)
		http.ServeContent(writer, r, "", time.Time{}, content.Body)
		return nil
	})
	if err != nil && writer.started {
		panic(http.ErrAbortHandler)
	}
	return nil, err
}
func (h *handler) reviewDownload(w http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
	writer := &trackingWriter{ResponseWriter: w}
	err := h.s.ReviewDownloadWithSize(r.Context(), p, r.PathValue("id"), func(size int64) {
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		writer.Header().Set("Content-Disposition", "attachment")
	}, writer)
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
