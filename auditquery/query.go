// Package auditquery defines the sanitized, authorized audit repository port.
// The host must authenticate and intersect current permissions before each call.
package auditquery

import (
	"context"
	"errors"
	"time"
)

var ErrInvalid = errors.New("audit_invalid_request")
var ErrUnavailable = errors.New("audit_snapshot_unavailable")

type Scope struct {
	School string `json:"school"`
	Group  string `json:"group"`
	Module string `json:"module"`
}
type Position struct {
	Time       time.Time
	Source, ID string
}

// Request mirrors platform admin.AuditRequest. Scopes are a union of authorized
// intersections, never caller-provided grants. Until is an exclusive upper bound.
type Request struct {
	Scopes                []Scope
	Actor, Target, Action string
	From, Until           time.Time
	Before                *Position
	Snapshot              string
	Limit                 int
}
type Record struct {
	ID, Source, Actor, Target, Action, Reason, Result string
	Scope                                             Scope
	CreatedAt                                         time.Time
}
type Batch struct {
	Records  []Record
	Snapshot string
}
type Reader interface {
	ReadAudit(context.Context, Request) (Batch, error)
}
