package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeaders_CSPHeaderPresent verifies that the SecurityHeaders middleware
// sets the Content-Security-Policy header on every response.
func TestSecurityHeaders_CSPHeaderPresent(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}
}

// TestSecurityHeaders_CSPValue verifies the CSP header value is a restrictive policy
// that does not use a wildcard (*), which would allow untrusted content sources.
func TestSecurityHeaders_CSPValue(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")

	// Must not use a wildcard source
	if strings.Contains(csp, "*") {
		t.Errorf("Content-Security-Policy must not use wildcard (*); got: %s", csp)
	}

	// Must restrict content to 'self' at minimum
	if !strings.Contains(csp, "'self'") && !strings.Contains(csp, "self") {
		t.Errorf("Content-Security-Policy should restrict to 'self' at minimum; got: %s", csp)
	}
}

// TestSecurityHeaders_InnerHandlerStillCalled verifies the middleware does not
// prevent the wrapped handler from executing normally.
func TestSecurityHeaders_InnerHandlerStillCalled(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Fatal("inner handler was not called by SecurityHeaders middleware")
	}
}

// TestSecurityHeaders_CSPHeaderOnErrorResponse verifies that the CSP header is
// present even when the wrapped handler returns an HTTP error status, ensuring
// no response escapes the security policy.
func TestSecurityHeaders_CSPHeaderOnErrorResponse(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing on error response")
	}
}

// TestSecurityHeaders_MultipleRequests verifies the CSP header is set independently
// on every request and is not absent after the first call (no shared-state bug).
func TestSecurityHeaders_MultipleRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := SecurityHeaders(inner)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		wrapped(rr, req)

		csp := rr.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("Content-Security-Policy header missing on request %d", i+1)
		}
	}
}
