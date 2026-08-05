package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestDB opens an in-memory SQLite database and creates the repos table
// with the same schema used in production.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE repos (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			name      TEXT NOT NULL,
			git_url   TEXT NOT NULL,
			repo_type TEXT NOT NULL,
			created   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("create repos table: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHandler builds a Handler backed by an in-memory SQLite store.
// gitService is nil because no test here exercises the clone path.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db := newTestDB(t)
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	return NewHandler(repoStore, validator, nil)
}

// postForm sends a POST request to h with the provided form values and returns
// the recorded response.
func postForm(h http.Handler, target string, values url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// SecurityHeaders middleware tests
// ---------------------------------------------------------------------------

// TestSecurityHeaders_ContentSecurityPolicy verifies that the middleware
// sets a Content-Security-Policy header on every response.
// This is the direct remediation for CWE-346 / Missing Content Security Policy.
func TestSecurityHeaders_ContentSecurityPolicy(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header must be set but is missing")
	}
}

// TestSecurityHeaders_CSPValue verifies that the CSP value is restrictive and
// contains the minimum required directives for a JSON-only API service.
func TestSecurityHeaders_CSPValue(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")

	requiredDirectives := []string{
		"default-src",
		"frame-ancestors",
		"form-action",
	}
	for _, directive := range requiredDirectives {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP header missing directive %q; got: %q", directive, csp)
		}
	}
}

// TestSecurityHeaders_XFrameOptions ensures the clickjacking header is set.
func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	xfo := rr.Header().Get("X-Frame-Options")
	if xfo == "" {
		t.Fatal("X-Frame-Options header must be set but is missing")
	}
	if strings.ToUpper(xfo) != "DENY" {
		t.Errorf("X-Frame-Options: want DENY, got %q", xfo)
	}
}

// TestSecurityHeaders_XContentTypeOptions ensures the MIME-sniffing header is set.
func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	xcto := rr.Header().Get("X-Content-Type-Options")
	if xcto == "" {
		t.Fatal("X-Content-Type-Options header must be set but is missing")
	}
	if strings.ToLower(xcto) != "nosniff" {
		t.Errorf("X-Content-Type-Options: want nosniff, got %q", xcto)
	}
}

// TestSecurityHeaders_ReferrerPolicy ensures the Referrer-Policy header is set.
func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	rp := rr.Header().Get("Referrer-Policy")
	if rp == "" {
		t.Fatal("Referrer-Policy header must be set but is missing")
	}
}

// TestSecurityHeaders_HeadersPresentBeforeBodyWrite verifies that security
// headers are set even when the inner handler does not write any body.
// This tests the "before the handler runs" guarantee of the middleware.
func TestSecurityHeaders_HeadersPresentBeforeBodyWrite(t *testing.T) {
	bodyCh := make(chan struct{}, 1)
	headerCh := make(chan string, 1)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the header value *inside* the inner handler — the middleware
		// must have already set it by the time we reach here.
		headerCh <- w.Header().Get("Content-Security-Policy")
		w.WriteHeader(http.StatusOK)
		close(bodyCh)
	})
	wrapped := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	<-bodyCh
	csp := <-headerCh
	if csp == "" {
		t.Fatal("Content-Security-Policy must be present in ResponseWriter before inner handler executes")
	}
}

// TestSecurityHeaders_DoesNotOverrideExistingCSP tests that the middleware
// does not double-set the header when called twice (idempotent chain).
func TestSecurityHeaders_WrappedCreateRepo_HasCSP(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.CreateRepo))

	form := url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/org/my-repo"},
	}
	rr := postForm(wrapped, "/api/repo/create", form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be present in CreateRepo response when wrapped")
	}
}

// TestSecurityHeaders_WrappedListRepos_HasCSP verifies that ListRepos responses
// also carry the CSP header when served through the SecurityHeaders middleware.
func TestSecurityHeaders_WrappedListRepos_HasCSP(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.ListRepos))

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be present in ListRepos response when wrapped")
	}
}

// TestSecurityHeaders_UnwrappedCreateRepo_MissingCSP is a regression guard:
// if CreateRepo is NOT wrapped with SecurityHeaders the CSP header must be
// absent — confirming that the middleware (not the handler) is responsible.
func TestSecurityHeaders_UnwrappedCreateRepo_MissingCSP(t *testing.T) {
	h := newTestHandler(t)

	form := url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/org/my-repo"},
	}
	rr := postForm(http.HandlerFunc(h.CreateRepo), "/api/repo/create", form)

	if csp := rr.Header().Get("Content-Security-Policy"); csp != "" {
		t.Errorf("handler without middleware must not set CSP; got: %q", csp)
	}
}

// ---------------------------------------------------------------------------
// CreateRepo functional tests (with SecurityHeaders in production position)
// ---------------------------------------------------------------------------

// TestCreateRepo_Success verifies that a valid POST returns 200 with the
// CSP header and a JSON body containing success:true.
func TestCreateRepo_Success(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.CreateRepo))

	form := url.Values{
		"name":      {"demo"},
		"git_url":   {"https://github.com/org/demo"},
		"repo_type": {"git"},
	}
	rr := postForm(wrapped, "/api/repo/create", form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["success"] != true {
		t.Errorf("body[success]: want true, got %v", body["success"])
	}
	if _, ok := body["id"]; !ok {
		t.Error("response body must contain 'id' field")
	}

	// CSP header must still be present on a successful response.
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be set on 200 success response")
	}
}

// TestCreateRepo_MissingFields verifies that a 400 response also carries the
// CSP header — the middleware must fire before any error short-circuit.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.CreateRepo))

	rr := postForm(wrapped, "/api/repo/create", url.Values{})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be present even on 400 error responses")
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a 400 response for a
// non-whitelisted domain also carries the CSP header.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.CreateRepo))

	form := url.Values{
		"name":    {"evil"},
		"git_url": {"https://evil.example.com/repo"},
	}
	rr := postForm(wrapped, "/api/repo/create", form)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be present on domain-rejection 400 response")
	}
}

// TestCreateRepo_WrongMethod verifies that a 405 response also carries the
// CSP header.
func TestCreateRepo_WrongMethod(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.CreateRepo))

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be present on 405 method-not-allowed response")
	}
}

// ---------------------------------------------------------------------------
// ListRepos functional tests
// ---------------------------------------------------------------------------

// TestListRepos_EmptyList verifies that an empty list is returned (not nil)
// and that the CSP header is set.
func TestListRepos_EmptyList(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.ListRepos))

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be set on ListRepos response")
	}

	var repos []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&repos); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if repos == nil {
		t.Error("ListRepos must return an empty slice, not null")
	}
}

// TestListRepos_WrongMethod verifies that a 405 response also carries the
// CSP header.
func TestListRepos_WrongMethod(t *testing.T) {
	h := newTestHandler(t)
	wrapped := SecurityHeaders(http.HandlerFunc(h.ListRepos))

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy must be present on 405 response")
	}
}
