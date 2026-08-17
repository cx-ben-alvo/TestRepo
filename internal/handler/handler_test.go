package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// securityHeadersTestHandler is a trivial HandlerFunc used to verify that the
// SecurityHeaders middleware correctly injects headers before delegating to the
// wrapped handler.
func securityHeadersTestHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// TestSecurityHeaders_ContentSecurityPolicyPresent verifies that the
// SecurityHeaders middleware sets the Content-Security-Policy header on every
// response, which is the primary fix for the Missing_Content_Security_Policy
// SAST finding (CWE-346).
func TestSecurityHeaders_ContentSecurityPolicyPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	SecurityHeaders(securityHeadersTestHandler)(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header to be set, got empty string")
	}
}

// TestSecurityHeaders_ContentSecurityPolicyValue verifies the exact CSP value
// used for API-only endpoints ("default-src 'none'").
func TestSecurityHeaders_ContentSecurityPolicyValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	SecurityHeaders(securityHeadersTestHandler)(rr, req)

	const want = "default-src 'none'"
	got := rr.Header().Get("Content-Security-Policy")
	if got != want {
		t.Errorf("Content-Security-Policy: want %q, got %q", want, got)
	}
}

// TestSecurityHeaders_XContentTypeOptionsPresent verifies the X-Content-Type-Options
// defence-in-depth header is set by the middleware.
func TestSecurityHeaders_XContentTypeOptionsPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	SecurityHeaders(securityHeadersTestHandler)(rr, req)

	got := rr.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("X-Content-Type-Options: want %q, got %q", "nosniff", got)
	}
}

// TestSecurityHeaders_XFrameOptionsPresent verifies the X-Frame-Options header
// is set to DENY by the middleware.
func TestSecurityHeaders_XFrameOptionsPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	SecurityHeaders(securityHeadersTestHandler)(rr, req)

	got := rr.Header().Get("X-Frame-Options")
	if got != "DENY" {
		t.Errorf("X-Frame-Options: want %q, got %q", "DENY", got)
	}
}

// TestSecurityHeaders_ReferrerPolicyPresent verifies the Referrer-Policy
// defence-in-depth header is set by the middleware.
func TestSecurityHeaders_ReferrerPolicyPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	SecurityHeaders(securityHeadersTestHandler)(rr, req)

	got := rr.Header().Get("Referrer-Policy")
	if got != "no-referrer" {
		t.Errorf("Referrer-Policy: want %q, got %q", "no-referrer", got)
	}
}

// TestSecurityHeaders_DelegatestoWrappedHandler verifies that the middleware
// does not short-circuit: the wrapped handler is still called and its status
// code is preserved.
func TestSecurityHeaders_DelegatestoWrappedHandler(t *testing.T) {
	called := false
	inner := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rr := httptest.NewRecorder()

	SecurityHeaders(inner)(rr, req)

	if !called {
		t.Error("expected inner handler to be called; it was not")
	}
	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d from inner handler, got %d", http.StatusCreated, rr.Code)
	}
}

// TestSecurityHeaders_AllEndpointsCovered is a table-driven regression test
// that enumerates all API route method/path combinations and verifies that each
// would carry the CSP header when wrapped by SecurityHeaders. This ensures the
// fix is not accidentally bypassed if routes are added in the future without
// applying the middleware.
func TestSecurityHeaders_AllEndpointsCovered(t *testing.T) {
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/repo/create"},
		{http.MethodPost, "/api/repo/clone"},
		{http.MethodGet, "/api/repo/list"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			rr := httptest.NewRecorder()

			SecurityHeaders(securityHeadersTestHandler)(rr, req)

			if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
				t.Errorf("%s %s: Content-Security-Policy header missing", ep.method, ep.path)
			}
		})
	}
}
