package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

const testToken = "s3cret-admin-token"

// adminHarness builds a handler whose admin API is backed by an in-memory store
// seeded with the given pending report ids, authenticated by token. It returns
// the handler and the store so tests can assert post-conditions.
func adminHarness(t *testing.T, token string, pendingIDs ...string) (http.Handler, storage.ObjectStore) {
	t.Helper()
	store := storage.NewMemoryStore()
	for _, id := range pendingIDs {
		// The admin API only lists keys and moves opaque bytes, so a placeholder
		// ciphertext is enough; no real crypto is needed to exercise it.
		if err := store.Put(context.Background(), storage.ReportKey(storage.StatusPending, id), []byte("frame:"+id)); err != nil {
			t.Fatalf("seed pending %q: %v", id, err)
		}
	}
	h := New(nil, NewManagerBackend(lifecycle.New(store), token))
	return h, store
}

// adminReq issues one admin request with an optional bearer token ("" sends no
// Authorization header) and returns the recorder.
func adminReq(t *testing.T, h http.Handler, method, target, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// adminBody is a decode target spanning every admin response field (list, remove,
// and error bodies), so one helper can parse any admin response in the tests.
type adminBody struct {
	Status  string   `json:"status"`
	Reports []string `json:"reports"`
	ID      string   `json:"id"`
	Error   string   `json:"error"`
}

// decodeAdmin parses an admin JSON response body.
func decodeAdmin(t *testing.T, rec *httptest.ResponseRecorder) adminBody {
	t.Helper()
	var got adminBody
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("admin response is not valid JSON: %v (body=%q)", err, rec.Body.String())
	}
	return got
}

// TestAdminListReturnsPendingIDs is the acceptance path: an authenticated
// maintainer lists exactly the pending report ids.
func TestAdminListReturnsPendingIDs(t *testing.T) {
	h, _ := adminHarness(t, testToken, "id-a", "id-b", "id-c")

	rec := adminReq(t, h, http.MethodGet, "/v1/admin/reports", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET list status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}
	got := decodeAdmin(t, rec)
	if got.Status != "ok" {
		t.Errorf("status field = %q, want ok", got.Status)
	}
	want := []string{"id-a", "id-b", "id-c"} // sorted, MemoryStore lists ascending
	if !slices.Equal(got.Reports, want) {
		t.Errorf("reports = %v, want %v", got.Reports, want)
	}
}

// TestAdminListEmptyIsArray confirms an empty pending set marshals as [] (not null),
// which the API consumers (and the Bruno tests) rely on.
func TestAdminListEmptyIsArray(t *testing.T) {
	h, _ := adminHarness(t, testToken)
	rec := adminReq(t, h, http.MethodGet, "/v1/admin/reports", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"reports":[]`) {
		t.Errorf("empty list body = %q, want it to contain \"reports\":[]", body)
	}
}

// TestAdminRemoveExcludesFromPending is the ticket's core acceptance: a removed
// report transitions to removed and disappears from the pending list, so the next
// publish run will not see it.
func TestAdminRemoveExcludesFromPending(t *testing.T) {
	h, store := adminHarness(t, testToken, "keep-1", "drop-me", "keep-2")

	rec := adminReq(t, h, http.MethodPost, "/v1/admin/reports/drop-me/remove", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if got := decodeAdmin(t, rec); got.Status != "removed" || got.ID != "drop-me" {
		t.Errorf("remove body = %+v, want {status:removed id:drop-me}", got)
	}

	// It is gone from the pending list...
	list := adminReq(t, h, http.MethodGet, "/v1/admin/reports", testToken)
	if got := decodeAdmin(t, list).Reports; slices.Contains(got, "drop-me") {
		t.Errorf("pending list still contains drop-me: %v", got)
	} else if !slices.Equal(got, []string{"keep-1", "keep-2"}) {
		t.Errorf("pending list = %v, want [keep-1 keep-2]", got)
	}

	// ...and it now lives under the removed prefix (excluded from publishing).
	removed, _ := store.List(context.Background(), storage.StatusPrefix(storage.StatusRemoved))
	if !slices.Equal(removed, []string{storage.ReportKey(storage.StatusRemoved, "drop-me")}) {
		t.Errorf("removed keys = %v, want the single removed report", removed)
	}
}

// TestAdminRemoveViaDelete checks the DELETE alias behaves like POST .../remove.
func TestAdminRemoveViaDelete(t *testing.T) {
	h, _ := adminHarness(t, testToken, "gone")
	rec := adminReq(t, h, http.MethodDelete, "/v1/admin/reports/gone", testToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	list := adminReq(t, h, http.MethodGet, "/v1/admin/reports", testToken)
	if got := decodeAdmin(t, list).Reports; len(got) != 0 {
		t.Errorf("pending after DELETE = %v, want empty", got)
	}
}

// TestAdminRemoveIdempotent proves removing the same report twice still succeeds
// (200), matching the lifecycle Manager's idempotent transition.
func TestAdminRemoveIdempotent(t *testing.T) {
	h, _ := adminHarness(t, testToken, "twice")
	if rec := adminReq(t, h, http.MethodPost, "/v1/admin/reports/twice/remove", testToken); rec.Code != http.StatusOK {
		t.Fatalf("first remove status = %d, want 200", rec.Code)
	}
	if rec := adminReq(t, h, http.MethodPost, "/v1/admin/reports/twice/remove", testToken); rec.Code != http.StatusOK {
		t.Errorf("second remove status = %d, want 200 (idempotent)", rec.Code)
	}
}

// TestAdminRemoveUnknownIs404 covers an id that was never pending.
func TestAdminRemoveUnknownIs404(t *testing.T) {
	h, _ := adminHarness(t, testToken, "real")
	rec := adminReq(t, h, http.MethodPost, "/v1/admin/reports/ghost/remove", testToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("remove unknown status = %d, want 404 (body=%q)", rec.Code, rec.Body.String())
	}
	if got := decodeAdmin(t, rec); got.Status != "error" {
		t.Errorf("404 status field = %q, want error", got.Status)
	}
}

// TestAdminMissingTokenIs401 covers a request with no Authorization header.
func TestAdminMissingTokenIs401(t *testing.T) {
	h, _ := adminHarness(t, testToken, "id-a")
	for _, tc := range []struct {
		name, method, target string
	}{
		{"list", http.MethodGet, "/v1/admin/reports"},
		{"remove", http.MethodPost, "/v1/admin/reports/id-a/remove"},
		{"delete", http.MethodDelete, "/v1/admin/reports/id-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := adminReq(t, h, tc.method, tc.target, "")
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("no-token status = %d, want 401", rec.Code)
			}
			if wa := rec.Header().Get("WWW-Authenticate"); wa != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", wa)
			}
		})
	}
	// A no-op check that the guarded report is still pending (auth blocked the write).
	list := adminReq(t, h, http.MethodGet, "/v1/admin/reports", testToken)
	if got := decodeAdmin(t, list).Reports; !slices.Contains(got, "id-a") {
		t.Errorf("report was mutated despite unauthorized requests: %v", got)
	}
}

// TestAdminInvalidTokenIs401 covers a well-formed header carrying the wrong token.
func TestAdminInvalidTokenIs401(t *testing.T) {
	h, _ := adminHarness(t, testToken, "id-a")
	rec := adminReq(t, h, http.MethodGet, "/v1/admin/reports", "wrong-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad-token status = %d, want 401", rec.Code)
	}
}

// TestAdminMalformedAuthHeaderIs401 covers non-Bearer / malformed schemes.
func TestAdminMalformedAuthHeaderIs401(t *testing.T) {
	h, _ := adminHarness(t, testToken, "id-a")
	for _, hdr := range []string{"Basic abc123", "Bearer", "token " + testToken, testToken} {
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/reports", nil)
		req.Header.Set("Authorization", hdr)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status = %d, want 401", hdr, rec.Code)
		}
	}
}

// TestAdminUnsetSecretFailsClosed is the fail-closed requirement: with no server
// secret configured, every request is rejected even when the client presents a
// (any) bearer token, so a missing binding can never leave the API open.
func TestAdminUnsetSecretFailsClosed(t *testing.T) {
	h, _ := adminHarness(t, "" /* no server secret */, "id-a")

	// Client presents a plausible token; the server has none, so 401.
	if rec := adminReq(t, h, http.MethodGet, "/v1/admin/reports", "any-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("list with unset server secret: status = %d, want 401", rec.Code)
	}
	if rec := adminReq(t, h, http.MethodPost, "/v1/admin/reports/id-a/remove", "any-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("remove with unset server secret: status = %d, want 401", rec.Code)
	}
	// The empty string as a token must not authenticate against an unset secret.
	if rec := adminReq(t, h, http.MethodGet, "/v1/admin/reports", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("list with no token and unset secret: status = %d, want 401", rec.Code)
	}
}

// TestAdminNilBackendFailsClosed proves New(sink, nil) still fails closed (401),
// never panics, and never allows access.
func TestAdminNilBackendFailsClosed(t *testing.T) {
	h := New(nil, nil)
	if rec := adminReq(t, h, http.MethodGet, "/v1/admin/reports", "any-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("nil backend list: status = %d, want 401", rec.Code)
	}
}

// TestAdminWrongMethodIs405 checks the mux answers 405 for a wrong method on a
// known admin path, with an Allow header, before auth runs.
func TestAdminWrongMethodIs405(t *testing.T) {
	h, _ := adminHarness(t, testToken, "id-a")
	for _, tc := range []struct {
		name, method, target, allow string
	}{
		{"put-list", http.MethodPut, "/v1/admin/reports", http.MethodGet},
		{"delete-list", http.MethodDelete, "/v1/admin/reports", http.MethodGet},
		{"get-remove", http.MethodGet, "/v1/admin/reports/id-a/remove", http.MethodPost},
		{"put-report", http.MethodPut, "/v1/admin/reports/id-a", http.MethodDelete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := adminReq(t, h, tc.method, tc.target, testToken)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != tc.allow {
				t.Errorf("Allow = %q, want %q", allow, tc.allow)
			}
		})
	}
}
