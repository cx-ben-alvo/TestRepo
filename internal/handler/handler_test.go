package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/handler"
)

// TestSecurityHeaders_ContentSecurityPolicy verifies that the SecurityHeaders
// middleware sets the Content-Security-Policy header on every response,
// which is the primary remediation for CWE-346 / Missing_Content_Security_Policy.
func TestSecurityHeaders_ContentSecurityPolicy(t *testing.T) {
	// A minimal next handler that simply returns 200 OK.
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.SecurityHeaders(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing from response")
	}
	// The value must restrict resource loading to the same origin at minimum.
	if csp != "default-src 'self'" {
		t.Errorf("unexpected Content-Security-Policy value: got %q, want %q", csp, "default-src 'self'")
	}
}

// TestSecurityHeaders_XContentTypeOptions verifies that X-Content-Type-Options
// is set to "nosniff" to prevent MIME-type confusion attacks.
func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.SecurityHeaders(next).ServeHTTP(rr, req)

	val := rr.Header().Get("X-Content-Type-Options")
	if val != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want %q", val, "nosniff")
	}
}

// TestSecurityHeaders_XFrameOptions verifies that X-Frame-Options is set to
// "DENY" to prevent clickjacking attacks.
func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.SecurityHeaders(next).ServeHTTP(rr, req)

	val := rr.Header().Get("X-Frame-Options")
	if val != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want %q", val, "DENY")
	}
}

// TestSecurityHeaders_XXSSProtection verifies that X-XSS-Protection is set
// to enable browser-level XSS filtering.
func TestSecurityHeaders_XXSSProtection(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.SecurityHeaders(next).ServeHTTP(rr, req)

	val := rr.Header().Get("X-XSS-Protection")
	if val != "1; mode=block" {
		t.Errorf("X-XSS-Protection: got %q, want %q", val, "1; mode=block")
	}
}

// TestSecurityHeaders_ForwardsToNextHandler verifies that the middleware
// calls the next handler and preserves its response body and status code.
func TestSecurityHeaders_ForwardsToNextHandler(t *testing.T) {
	const wantBody = `{"ok":true}`
	const wantStatus = http.StatusCreated

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(wantStatus)
		w.Write([]byte(wantBody))
	})

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	handler.SecurityHeaders(next).ServeHTTP(rr, req)

	if rr.Code != wantStatus {
		t.Errorf("status code: got %d, want %d", rr.Code, wantStatus)
	}
	if rr.Body.String() != wantBody {
		t.Errorf("response body: got %q, want %q", rr.Body.String(), wantBody)
	}
}

// TestSecurityHeaders_AllHeadersPresentTogether verifies all required security
// headers are set in a single request — prevents the regression of any one
// header being accidentally removed.
func TestSecurityHeaders_AllHeadersPresentTogether(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	handler.SecurityHeaders(next).ServeHTTP(rr, req)

	requiredHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
	}

	for header, wantValue := range requiredHeaders {
		gotValue := rr.Header().Get(header)
		if gotValue == "" {
			t.Errorf("security header %q is missing from the response", header)
		} else if gotValue != wantValue {
			t.Errorf("security header %q: got %q, want %q", header, gotValue, wantValue)
		}
	}
}

// TestSecurityHeaders_HeadersSetBeforeNextHandler verifies that headers are
// set even when the next handler also modifies headers (no ordering issue).
func TestSecurityHeaders_HeadersSetBeforeNextHandler(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a handler that also sets Content-Type — headers set by the
		// middleware should not be overwritten by the inner handler.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.SecurityHeaders(next).ServeHTTP(rr, req)

	if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header must be present even when inner handler also sets headers")
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("inner handler's Content-Type header was lost: got %q", ct)
	}
}

// TestSecurityHeaders_MultipleRequests verifies that security headers are
// correctly set on every request (not just the first one), preventing
// state-leak bugs in middleware implementations.
func TestSecurityHeaders_MultipleRequests(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := handler.SecurityHeaders(next)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		if csp := rr.Header().Get("Content-Security-Policy"); csp == "" {
			t.Errorf("request %d: Content-Security-Policy header missing", i+1)
		}
	}
}
