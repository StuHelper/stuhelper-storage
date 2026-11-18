package httpapi

import (
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
		mountEndpoint(m, path, routeOptions{
			auth:            a,
			public:          public,
			timeout:         time.Minute,
			maxBodyBytes:    16384,
			unavailableCode: "identity_unavailable",

			successStatus: func(r *http.Request) int {
				if r.Method == "POST" {
					return 202
				}
				return 200
			},
		}, func(_ http.ResponseWriter, r *http.Request, p storage.Principal) (any, error) {
			return run(r, p)
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
