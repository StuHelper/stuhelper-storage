package storage

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// Diagnostic carries sanitized, bounded failure metadata for server-side
// observability hooks. Raw error messages, URLs, SQL text and credentials
// are never accepted.
type Diagnostic struct {
	Component  string
	Operation  string
	ObjectID   string
	JobID      string
	Category   string
	HTTPStatus int
}

// Observer receives sanitized runtime diagnostics without altering error returns.
type Observer interface {
	Observe(Diagnostic)
}

func sanitizeDiagnosticToken(v string) string {
	if v == "" {
		return ""
	}
	if identifier.MatchString(v) {
		return v
	}
	return "redacted"
}

// EmitDiagnostic sanitizes every field before invoking obs so untrusted or
// raw transport strings cannot escape through observability hooks.
func EmitDiagnostic(obs Observer, d Diagnostic) {
	if obs == nil {
		return
	}
	d.Component = sanitizeDiagnosticToken(d.Component)
	d.Operation = sanitizeDiagnosticToken(d.Operation)
	d.ObjectID = sanitizeDiagnosticToken(d.ObjectID)
	d.JobID = sanitizeDiagnosticToken(d.JobID)
	d.Category = sanitizeDiagnosticToken(d.Category)
	if d.HTTPStatus < 100 || d.HTTPStatus > 599 {
		d.HTTPStatus = 0
	}
	obs.Observe(d)
}

func diagnosticCategory(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ErrInput):
		return "storage_invalid_input"
	case errors.Is(err, ErrDenied):
		return "storage_permission_denied"
	case errors.Is(err, ErrNotFound):
		return "storage_not_found"
	case errors.Is(err, ErrConflict):
		return "storage_conflict"
	case errors.Is(err, ErrCapacity):
		return "storage_capacity_unavailable"
	case errors.Is(err, ErrIntegrity):
		return "storage_integrity_failed"
	case errors.Is(err, ErrStale):
		return "storage_stale_operation"
	case errors.Is(err, ErrUnknown):
		return "storage_remote_result_unknown"
	default:
		return "storage_unavailable"
	}
}

func (s *Service) observe(op, objectID, jobID string, err error) {
	if err == nil || s.cfg.Observer == nil {
		return
	}
	EmitDiagnostic(s.cfg.Observer, Diagnostic{
		Component: "storage",
		Operation: op,
		ObjectID:  objectID,
		JobID:     jobID,
		Category:  diagnosticCategory(err),
	})
}

// RuntimeMetrics exposes read-only staging, transfer slot and bandwidth pacer
// counters for process-local monitoring.
type RuntimeMetrics struct {
	StagingLimitBytes    int64
	StagingReservedBytes int64
	StagingFiles         int
	ParallelTransfers    int
	ActiveTransfers      int
	Stopping             bool
	BandwidthRateBytes   int64
	BandwidthWaits       uint64
	BandwidthWaitNanos   uint64
}

func (s *Service) RuntimeMetrics() RuntimeMetrics {
	s.lifecycle.Lock()
	active := s.active
	stopping := s.stopping
	parallel := cap(s.slots)
	s.lifecycle.Unlock()

	limit, reserved, files := s.staging.stats()
	rate, waits, waitNanos := s.bandwidth.stats()
	return RuntimeMetrics{
		StagingLimitBytes:    limit,
		StagingReservedBytes: reserved,
		StagingFiles:         files,
		ParallelTransfers:    parallel,
		ActiveTransfers:      active,
		Stopping:             stopping,
		BandwidthRateBytes:   rate,
		BandwidthWaits:       waits,
		BandwidthWaitNanos:   waitNanos,
	}
}

type traceParentKey struct{}

var traceParentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

// WithTraceParent attaches a validated W3C traceparent value to ctx for Outbox
// CloudEvents propagation. Invalid values are ignored.
func WithTraceParent(ctx context.Context, traceParent string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	v := strings.TrimSpace(traceParent)
	if !traceParentPattern.MatchString(v) {
		return ctx
	}
	parts := strings.Split(v, "-")
	if parts[1] == "00000000000000000000000000000000" || parts[2] == "0000000000000000" {
		return ctx
	}
	return context.WithValue(ctx, traceParentKey{}, v)
}

// TraceParentFromContext returns the validated W3C traceparent stored in ctx, if any.
func TraceParentFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(traceParentKey{}).(string)
	return v
}

func eventSchoolID(p Protection) string {
	if validID(p.Scope) && p.Scope != "global" && p.Scope != "platform" {
		return p.Scope
	}
	return ""
}
