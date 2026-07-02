package handler

// Maintainer admin API (#11): an authenticated path for the single maintainer to
// review the pending queue and pull a report before the weekly publish run.
//
//	GET    /v1/admin/reports              -> 200 {"status":"ok","reports":[<id>...]}
//	POST   /v1/admin/reports/{id}/remove  -> 200 {"status":"removed","id":<id>}
//	DELETE /v1/admin/reports/{id}         -> 200 {"status":"removed","id":<id>}  (alias)
//
// Removing a report transitions it pending -> removed via the lifecycle Manager
// (#10); #13's ListPending no longer returns it, so it is excluded from the next
// Friday publish. Remove is idempotent (removing an already-removed report still
// succeeds); an id that was never pending returns 404.
//
// # Authentication
//
// A shared-secret bearer token, chosen over Cloudflare Access for a
// single-maintainer, low-volume tool: it needs no Zero Trust org/policy setup,
// is trivially callable from curl/scripts/CI, and injects cleanly for tests and
// the dev server. See docs/decisions/admin-auth.md.
//
// Every admin request must carry `Authorization: Bearer <token>`. The presented
// token is compared to the configured secret with crypto/subtle.ConstantTimeCompare
// so a wrong token cannot be recovered by timing. The endpoint fails closed: if
// the server has no secret configured (unset/empty), every request is rejected
// with 401 regardless of what the client sends, so a missing binding can never
// silently disable auth. Missing/malformed/wrong credentials also return 401 with
// a `WWW-Authenticate: Bearer` challenge.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
)

// AdminBackend supplies the admin API's dependencies. It is an interface, not a
// concrete *lifecycle.Manager, so the same routes serve both deployment targets:
// the host (dev server, tests) wires a static Manager + injected token via
// NewManagerBackend, while the Cloudflare Worker wires a lazy implementation that
// reads the token from Secrets Store and builds an R2-backed Manager per request
// (the token and the R2 binding are only available inside a request there).
type AdminBackend interface {
	// AdminToken returns the configured shared secret, or "" if none is set (in
	// which case auth fails closed). ctx-scoped so the Worker can read Secrets
	// Store per request. A non-nil error (e.g. a failed secret load) yields 503.
	AdminToken(ctx context.Context) (string, error)
	// ListPending returns the ids of all pending reports (lifecycle.Manager.ListPending).
	ListPending(ctx context.Context) ([]string, error)
	// MarkRemoved transitions a pending report to removed (lifecycle.Manager.MarkRemoved),
	// returning lifecycle.ErrUnknownReport if the id is not pending.
	MarkRemoved(ctx context.Context, id string) error
}

// managerBackend adapts a ready *lifecycle.Manager and a fixed shared secret to
// AdminBackend. It is the host wiring (dev server, tests); the Worker supplies
// its own lazy backend.
type managerBackend struct {
	mgr   *lifecycle.Manager
	token string
}

// NewManagerBackend wires an injected *lifecycle.Manager and shared secret into
// an AdminBackend for the dev server and tests. An empty token leaves the admin
// API authenticated-but-unopenable (every request 401s), which is the intended
// fail-closed behaviour when no secret is provisioned.
func NewManagerBackend(mgr *lifecycle.Manager, token string) AdminBackend {
	return managerBackend{mgr: mgr, token: token}
}

func (b managerBackend) AdminToken(context.Context) (string, error) { return b.token, nil }

func (b managerBackend) ListPending(ctx context.Context) ([]string, error) {
	return b.mgr.ListPending(ctx)
}

func (b managerBackend) MarkRemoved(ctx context.Context, id string) error {
	return b.mgr.MarkRemoved(ctx, id)
}

// denyAllBackend is substituted when New is called with a nil AdminBackend. It
// reports an empty secret, so authentication always fails closed (401) and the
// list/remove methods are never reached.
type denyAllBackend struct{}

func (denyAllBackend) AdminToken(context.Context) (string, error)    { return "", nil }
func (denyAllBackend) ListPending(context.Context) ([]string, error) { return nil, errNotConfigured }
func (denyAllBackend) MarkRemoved(context.Context, string) error     { return errNotConfigured }

var errNotConfigured = errors.New("handler: admin backend not configured")

// adminAPI holds the admin route handlers over an AdminBackend.
type adminAPI struct {
	backend AdminBackend
}

// register mounts the admin routes on mux. Patterns are method-agnostic and each
// handler dispatches on the method itself, matching the rest of this package
// (isGet, the ingest handler): a broad "/" catch-all is also registered on the
// same mux, and it would otherwise absorb a method-mismatched request before the
// mux's own 405 logic could fire, so the method check lives in-handler.
func (a *adminAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("/v1/admin/reports", a.reports)
	mux.HandleFunc("/v1/admin/reports/{id}/remove", a.removeViaPost)
	mux.HandleFunc("/v1/admin/reports/{id}", a.removeViaDelete)
}

// reports serves /v1/admin/reports: GET lists the pending report ids.
func (a *adminAPI) reports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !a.authorize(w, r) {
		return
	}
	ids, err := a.backend.ListPending(r.Context())
	if err != nil {
		writeAdmin(w, http.StatusServiceUnavailable, adminResponse{Status: "error", Error: "admin backend unavailable"})
		return
	}
	if ids == nil {
		ids = []string{} // marshal an empty JSON array, never null
	}
	writeAdmin(w, http.StatusOK, adminList{Status: "ok", Reports: ids})
}

// removeViaPost serves POST /v1/admin/reports/{id}/remove.
func (a *adminAPI) removeViaPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	a.remove(w, r)
}

// removeViaDelete serves DELETE /v1/admin/reports/{id}, the REST-style alias for
// removeViaPost.
func (a *adminAPI) removeViaDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		methodNotAllowed(w, http.MethodDelete)
		return
	}
	a.remove(w, r)
}

// remove transitions the {id} report pending -> removed, after authenticating.
func (a *adminAPI) remove(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	id := r.PathValue("id")
	err := a.backend.MarkRemoved(r.Context(), id)
	switch {
	case err == nil:
		writeAdmin(w, http.StatusOK, adminResponse{Status: "removed", ID: id})
	case errors.Is(err, lifecycle.ErrUnknownReport):
		writeAdmin(w, http.StatusNotFound, adminResponse{Status: "error", Error: "unknown report"})
	default:
		writeAdmin(w, http.StatusServiceUnavailable, adminResponse{Status: "error", Error: "admin backend unavailable"})
	}
}

// methodNotAllowed writes a 405 with the Allow header advertising the one method
// the admin route accepts.
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeAdmin(w, http.StatusMethodNotAllowed, adminResponse{Status: "error", Error: "method not allowed"})
}

// authorize enforces the shared-secret bearer token. It returns true when the
// request is authenticated; otherwise it writes a 401 (missing/bad token or unset
// server secret) or 503 (secret load failed) and returns false. The comparison is
// constant-time and the endpoint fails closed on an empty configured secret.
func (a *adminAPI) authorize(w http.ResponseWriter, r *http.Request) bool {
	secret, err := a.backend.AdminToken(r.Context())
	if err != nil {
		writeAdmin(w, http.StatusServiceUnavailable, adminResponse{Status: "error", Error: "admin backend unavailable"})
		return false
	}
	if secret == "" || !bearerMatches(r.Header.Get("Authorization"), secret) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeAdmin(w, http.StatusUnauthorized, adminResponse{Status: "error", Error: "unauthorized"})
		return false
	}
	return true
}

// bearerMatches reports whether the Authorization header carries a Bearer token
// equal to secret. The scheme is matched case-insensitively (per RFC 7235); the
// token is compared in constant time. secret is assumed non-empty (the caller
// fails closed on an empty secret before calling this).
func bearerMatches(header, secret string) bool {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(secret)) == 1
}

// adminList is the GET /v1/admin/reports success body. Reports has no omitempty,
// so an empty pending set still marshals as {"reports":[]} (an array, never null),
// which clients and the Bruno tests rely on.
type adminList struct {
	Status  string   `json:"status"`
	Reports []string `json:"reports"`
}

// adminResponse is the JSON body shape for the remove and error responses.
type adminResponse struct {
	Status string `json:"status"`
	ID     string `json:"id,omitempty"`
	Error  string `json:"error,omitempty"`
}

func writeAdmin(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
