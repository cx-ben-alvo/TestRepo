package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSetSecurityHeaders verifies that setSecurityHeaders writes all required
// security headers (Content-Security-Policy, X-Content-Type-Options,
// X-Frame-Options) onto the response writer. This is the primary regression
// test for the CWE-346 / Missing Content Security Policy remediation.
func TestSetSecurityHeaders(t *testing.T) {
	rr := httptest.NewRecorder()
	setSecurityHeaders(rr)

	tests := []struct {
		header string
		want   string
	}{
		{
			header: "Content-Security-Policy",
			want:   contentSecurityPolicy,
		},
		{
			header: "X-Content-Type-Options",
			want:   "nosniff",
		},
		{
			header: "X-Frame-Options",
			want:   "DENY",
		},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			got := rr.Header().Get(tc.header)
			if got != tc.want {
				t.Errorf("header %q = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestContentSecurityPolicyValue verifies that the CSP constant restricts
// resources to same-origin, blocks framing, and disables dangerous object
// embedding.
func TestContentSecurityPolicyValue(t *testing.T) {
	requiredDirectives := []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
	}

	for _, directive := range requiredDirectives {
		t.Run(directive, func(t *testing.T) {
			if !strings.Contains(contentSecurityPolicy, directive) {
				t.Errorf(
					"contentSecurityPolicy missing directive %q; got: %q",
					directive, contentSecurityPolicy,
				)
			}
		})
	}
}

// TestCreateRepoCSPHeader verifies that the /api/repo/create handler sets
// the Content-Security-Policy header even when the request is rejected early
// (method not allowed), confirming the header is applied before any branching.
func TestCreateRepoCSPHeader(t *testing.T) {
	h := &Handler{
		// repoStore, validator and gitService are nil — the handler must reach
		// the method-not-allowed branch before using them.
	}

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing on CreateRepo response")
	}
	if csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

// TestCloneRepoCSPHeader verifies that the CloneRepo handler sets the
// Content-Security-Policy header on early-exit (method not allowed) responses.
func TestCloneRepoCSPHeader(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodGet, "/api/repo/clone", nil)
	rr := httptest.NewRecorder()

	h.CloneRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing on CloneRepo response")
	}
	if csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

// TestListReposCSPHeader verifies that the ListRepos handler sets the
// Content-Security-Policy header on early-exit (method not allowed) responses.
func TestListReposCSPHeader(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	rr := httptest.NewRecorder()

	h.ListRepos(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing on ListRepos response")
	}
	if csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

// TestXFrameOptionsOnAllHandlers verifies that all handlers set X-Frame-Options
// to DENY, preventing clickjacking attacks.
func TestXFrameOptionsOnAllHandlers(t *testing.T) {
	h := &Handler{}

	handlers := []struct {
		name    string
		method  string
		path    string
		fn      func(http.ResponseWriter, *http.Request)
	}{
		{"CreateRepo", http.MethodGet, "/api/repo/create", h.CreateRepo},
		{"CloneRepo", http.MethodGet, "/api/repo/clone", h.CloneRepo},
		{"ListRepos", http.MethodPost, "/api/repo/list", h.ListRepos},
	}

	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()

			tc.fn(rr, req)

			got := rr.Header().Get("X-Frame-Options")
			if got != "DENY" {
				t.Errorf("%s: X-Frame-Options = %q, want %q", tc.name, got, "DENY")
			}
		})
	}
}

// TestXContentTypeOptionsOnAllHandlers verifies that all handlers set
// X-Content-Type-Options to "nosniff", preventing MIME-sniffing attacks.
func TestXContentTypeOptionsOnAllHandlers(t *testing.T) {
	h := &Handler{}

	handlers := []struct {
		name   string
		method string
		path   string
		fn     func(http.ResponseWriter, *http.Request)
	}{
		{"CreateRepo", http.MethodGet, "/api/repo/create", h.CreateRepo},
		{"CloneRepo", http.MethodGet, "/api/repo/clone", h.CloneRepo},
		{"ListRepos", http.MethodPost, "/api/repo/list", h.ListRepos},
	}

	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()

			tc.fn(rr, req)

			got := rr.Header().Get("X-Content-Type-Options")
			if got != "nosniff" {
				t.Errorf("%s: X-Content-Type-Options = %q, want %q", tc.name, got, "nosniff")
			}
		})
	}
}
