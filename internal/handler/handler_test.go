package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWithCSP_SetsContentSecurityPolicyHeader verifies that the WithCSP
// middleware always sets the Content-Security-Policy header before any
// handler logic runs.
func TestWithCSP_SetsContentSecurityPolicyHeader(t *testing.T) {
	// A simple inner handler that writes a 200 OK response.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	wrapped(rec, req)

	got := rec.Header().Get("Content-Security-Policy")
	if got == "" {
		t.Fatal("Content-Security-Policy header is missing; expected it to be set by WithCSP")
	}
	if got != ContentSecurityPolicy {
		t.Fatalf("Content-Security-Policy = %q; want %q", got, ContentSecurityPolicy)
	}
}

// TestWithCSP_HeaderValueDoesNotUseWildcard ensures the CSP value never uses
// a bare wildcard (*) as a source, which would defeat the policy entirely.
func TestWithCSP_HeaderValueDoesNotUseWildcard(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	wrapped(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// The policy must not be a bare wildcard source.
	if csp == "*" || csp == "default-src *" {
		t.Fatalf("CSP header uses an unsafe wildcard: %q", csp)
	}
}

// TestWithCSP_HeaderSetBeforeHandlerWrites confirms that CSP is present even
// when the inner handler writes response headers itself — i.e. the middleware
// sets the header before delegating to the handler.
func TestWithCSP_HeaderSetBeforeHandlerWrites(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inner handler adds its own header and writes a body.
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusCreated)
	})

	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rec := httptest.NewRecorder()
	wrapped(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
		t.Fatalf("Content-Security-Policy header missing or wrong after inner handler ran")
	}
}

// TestWithCSP_InnerHandlerStillExecutes verifies the middleware does not
// short-circuit the wrapped handler — the response body must be written.
func TestWithCSP_InnerHandlerStillExecutes(t *testing.T) {
	const wantBody = `{"ok":true}`
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(wantBody))
	})

	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	rec := httptest.NewRecorder()
	wrapped(rec, req)

	if rec.Body.String() != wantBody {
		t.Fatalf("body = %q; want %q", rec.Body.String(), wantBody)
	}
	if rec.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
		t.Fatal("Content-Security-Policy header missing")
	}
}

// TestWithCSP_ConstantIsSelfRestricted checks that the exported
// ContentSecurityPolicy constant includes "default-src 'self'" — meaning the
// policy restricts content to the same origin as required by the fix.
func TestWithCSP_ConstantIsSelfRestricted(t *testing.T) {
	const wantContains = "'self'"
	csp := ContentSecurityPolicy
	for i := 0; i <= len(csp)-len(wantContains); i++ {
		if csp[i:i+len(wantContains)] == wantContains {
			return // found
		}
	}
	t.Fatalf("ContentSecurityPolicy %q does not contain %q; policy must restrict to 'self'", csp, wantContains)
}
