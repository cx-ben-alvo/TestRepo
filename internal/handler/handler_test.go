package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityHeaders_CSPHeaderPresent verifies that the SecurityHeaders middleware
// sets the Content-Security-Policy header on every response (CWE-346 remediation).
func TestSecurityHeaders_CSPHeaderPresent(t *testing.T) {
	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !innerCalled {
		t.Fatal("SecurityHeaders middleware did not call the inner handler")
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing; CSP must be set on all responses")
	}
}

// TestSecurityHeaders_CSPValue verifies the CSP value is the expected restrictive policy.
func TestSecurityHeaders_CSPValue(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	want := "default-src 'none'"
	got := rr.Header().Get("Content-Security-Policy")
	if got != want {
		t.Errorf("Content-Security-Policy = %q; want %q", got, want)
	}
}

// TestSecurityHeaders_AdditionalDefensiveHeaders verifies that companion security headers
// are also set by the middleware.
func TestSecurityHeaders_AdditionalDefensiveHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	tests := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "no-referrer"},
	}

	for _, tc := range tests {
		got := rr.Header().Get(tc.header)
		if got != tc.want {
			t.Errorf("%s = %q; want %q", tc.header, got, tc.want)
		}
	}
}

// TestSecurityHeaders_PropagatesStatusCode verifies that the middleware does not
// interfere with the HTTP status code written by the inner handler.
func TestSecurityHeaders_PropagatesStatusCode(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status code = %d; want %d", rr.Code, http.StatusCreated)
	}
}

// TestSecurityHeaders_HeadersPresentOnErrorResponses verifies that security headers
// are set even when the inner handler writes an error status.
func TestSecurityHeaders_HeadersPresentOnErrorResponses(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy header must be present even on error responses")
	}
}
