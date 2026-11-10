package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage/custody"
)

func NewCustody(s *custody.Service, a Authenticator) (http.Handler, error) {
	if s == nil || a == nil {
		return nil, storage.ErrInput
	}
	m := http.NewServeMux()
	base := "/api/v1/storage/custody"
	mount := func(path string, public bool, run func(*http.Request, storage.Principal) (any, error)) {
		m.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
			defer cancel()
			r = r.WithContext(ctx)
			deadline, _ := ctx.Deadline()
			controller := http.NewResponseController(w)
			_ = controller.SetReadDeadline(deadline)
			_ = controller.SetWriteDeadline(deadline)
			r.Body = http.MaxBytesReader(w, r.Body, 16384)
			var p storage.Principal
			if !public {
				var e error
				p, e = a.Authenticate(r)
				if e != nil || !p.Valid() {
					if errors.Is(e, storage.ErrUnavailable) {
						respondError(w, e)
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
			out, e := run(r, p)
			if e != nil {
				respondError(w, e)
				return
			}
			status := 200
			if r.Method == "POST" {
				status = 202
			}
			writeJSON(w, status, out)
		})
	}
	mount("GET "+base+"/policy", true, func(*http.Request, storage.Principal) (any, error) { return s.Policy(), nil })
	for _, admin := range []bool{false, true} {
		path := base
		if admin {
			path += "/operations"
		}
		mount("GET "+path, false, func(r *http.Request, p storage.Principal) (any, error) {
			n := 20
			if r.URL.Query().Has("limit") {
				var e error
				n, e = strconv.Atoi(r.URL.Query().Get("limit"))
				if e != nil {
					return nil, storage.ErrInput
				}
			}
			return s.List(r.Context(), p, n, r.URL.Query().Get("after"), admin)
		})
		mount("POST "+path+"/{id}/resume", false, func(r *http.Request, p storage.Principal) (any, error) {
			q, e := decode[custody.ResumeRequest](r)
			if e != nil {
				return nil, e
			}
			return s.Resume(r.Context(), p, r.PathValue("id"), q, admin)
		})
	}
	for _, path := range []string{base, base + "/{id}/reauthorize"} {
		mount("POST "+path, false, func(r *http.Request, p storage.Principal) (any, error) {
			q, e := decode[custody.Request](r)
			if e != nil {
				return nil, e
			}
			defer clear(q.Credential)
			return s.Submit(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), q)
		})
	}
	mount("GET "+base+"/requests/{id}", false, func(r *http.Request, p storage.Principal) (any, error) {
		return s.GetRequest(r.Context(), p, r.PathValue("id"))
	})
	return m, nil
}
