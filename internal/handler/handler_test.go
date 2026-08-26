package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/service"
)

// cspHeader is the header name for Content-Security-Policy.
const cspHeader = "Content-Security-Policy"

// expectedCSP is the policy value that must appear on every response.
const expectedCSP = "default-src 'self'"

// TestWithSecurityHeaders_SetsCSPHeader verifies that WithSecurityHeaders adds
// the Content-Security-Policy header before the wrapped handler runs.
func TestWithSecurityHeaders_SetsCSPHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("expected %q header to be set; got empty string", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("%q header: got %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestWithSecurityHeaders_CSPNotWildcard verifies that the policy does not use
// a wildcard (*) source, which would defeat the protection entirely.
func TestWithSecurityHeaders_CSPNotWildcard(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	csp := rr.Header().Get(cspHeader)
	if strings.Contains(csp, "*") {
		t.Errorf("%q header must not use wildcard (*), got %q", cspHeader, csp)
	}
}

// TestWithSecurityHeaders_InnerHandlerStillRuns verifies that the middleware
// does not swallow the response from the wrapped handler.
func TestWithSecurityHeaders_InnerHandlerStillRuns(t *testing.T) {
	const wantStatus = http.StatusAccepted
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(wantStatus)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != wantStatus {
		t.Errorf("inner handler status: got %d, want %d", rr.Code, wantStatus)
	}
}

// TestWithSecurityHeaders_CSPPresentOnErrorResponses verifies that the CSP
// header is present even when the inner handler writes an error response.
// This matters because error paths are the most likely to be missed by a
// handler-level (rather than middleware-level) header approach.
func TestWithSecurityHeaders_CSPPresentOnErrorResponses(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("%q header must be set even on error responses; got empty string", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("%q on error response: got %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCSPDefaultSrcSelf_NotEmpty verifies the policy value is non-trivially
// populated — it must not be blank or contain only whitespace.
func TestCSPDefaultSrcSelf_NotEmpty(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	csp := rr.Header().Get(cspHeader)
	if strings.TrimSpace(csp) == "" {
		t.Errorf("%q header must not be empty or whitespace-only", cspHeader)
	}
}

// TestCreateRepo_MethodNotAllowed_HasCSPHeader verifies that the CSP header is
// present when CreateRepo rejects a non-POST request — an early-exit code path.
func TestCreateRepo_MethodNotAllowed_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CreateRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CreateRepo (405 path): %q header not set; got empty string", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CreateRepo (405 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCreateRepo_MissingFields_HasCSPHeader verifies that the CSP header is
// present when CreateRepo returns 400 for missing required fields.
func TestCreateRepo_MissingFields_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CreateRepo)

	// POST with no body fields → name and git_url will be empty.
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CreateRepo (400 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CreateRepo (400 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCloneRepo_MethodNotAllowed_HasCSPHeader verifies that the CSP header is
// present when CloneRepo rejects a non-POST request.
func TestCloneRepo_MethodNotAllowed_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CloneRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/clone", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CloneRepo (405 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CloneRepo (405 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCloneRepo_MissingRepoID_HasCSPHeader verifies that the CSP header is
// present when CloneRepo returns 400 for a missing repo_id field.
func TestCloneRepo_MissingRepoID_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CloneRepo)

	// POST with no body fields → repo_id will be empty.
	req := httptest.NewRequest(http.MethodPost, "/api/repo/clone", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CloneRepo (400 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CloneRepo (400 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestListRepos_MethodNotAllowed_HasCSPHeader verifies that the CSP header is
// present when ListRepos rejects a non-GET request.
func TestListRepos_MethodNotAllowed_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.ListRepos)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("ListRepos (405 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("ListRepos (405 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}
