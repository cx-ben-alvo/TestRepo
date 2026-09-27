package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityHeaders_CSPPresent verifies that SecurityHeaders middleware
// sets the Content-Security-Policy header on every response.
func TestSecurityHeaders_CSPPresent(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}
}

// TestSecurityHeaders_CSPValue verifies the CSP header is not a wildcard and
// restricts sources to 'self'.
func TestSecurityHeaders_CSPValue(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	const want = "default-src 'self'"
	if csp != want {
		t.Errorf("Content-Security-Policy = %q; want %q", csp, want)
	}
}

// TestSecurityHeaders_NoWildcard ensures the policy does not use a bare
// wildcard ('*'), which would allow content from any external resource.
func TestSecurityHeaders_NoWildcard(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	for _, ch := range csp {
		if ch == '*' {
			t.Errorf("Content-Security-Policy must not contain a wildcard '*': got %q", csp)
			return
		}
	}
}

// TestSecurityHeaders_InnerHandlerStillCalled verifies that the inner handler
// is invoked and its response body / status code are preserved.
func TestSecurityHeaders_InnerHandlerStillCalled(t *testing.T) {
	const wantStatus = http.StatusCreated
	const wantBody = "ok"

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(wantStatus)
		w.Write([]byte(wantBody)) //nolint:errcheck
	})

	handler := SecurityHeaders(inner)
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != wantStatus {
		t.Errorf("status = %d; want %d", rec.Code, wantStatus)
	}
	if got := rec.Body.String(); got != wantBody {
		t.Errorf("body = %q; want %q", got, wantBody)
	}
}

// TestSecurityHeaders_MultipleRequests verifies the CSP header is set on
// every request, not just the first one (guards against one-shot middleware).
func TestSecurityHeaders_MultipleRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)

		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatalf("request %d: Content-Security-Policy header is missing", i+1)
		}
	}
}
