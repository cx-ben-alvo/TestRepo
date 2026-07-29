package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityHeaders_CSPHeaderIsPresent verifies that the Content-Security-Policy
// header is set on every response wrapped by the SecurityHeaders middleware.
func TestSecurityHeaders_CSPHeaderIsPresent(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing; response is vulnerable to XSS/data-injection attacks")
	}
}

// TestSecurityHeaders_CSPHeaderValue verifies that the Content-Security-Policy
// value contains the mandatory directives (default-src and frame-ancestors).
func TestSecurityHeaders_CSPHeaderValue(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	expectedValue := "default-src 'none'; frame-ancestors 'none'"
	if csp != expectedValue {
		t.Errorf("Content-Security-Policy header value = %q; want %q", csp, expectedValue)
	}
}

// TestSecurityHeaders_AdditionalSecurityHeaders verifies that complementary
// security headers are also present to provide defence-in-depth.
func TestSecurityHeaders_AdditionalSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	cases := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"X-XSS-Protection", "1; mode=block"},
		{"Referrer-Policy", "no-referrer"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		got := rr.Header().Get(tc.header)
		if got != tc.want {
			t.Errorf("header %q = %q; want %q", tc.header, got, tc.want)
		}
	}
}

// TestSecurityHeaders_InnerHandlerStillCalled confirms that the middleware
// does not short-circuit the wrapped handler — the underlying logic still runs.
func TestSecurityHeaders_InnerHandlerStillCalled(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("SecurityHeaders middleware prevented the inner handler from being called")
	}
	if rr.Code != http.StatusNoContent {
		t.Errorf("response status = %d; want %d", rr.Code, http.StatusNoContent)
	}
}

// TestSecurityHeaders_HeadersSetBeforeInnerHandler verifies that security
// headers are set regardless of what status code the inner handler writes,
// covering error responses (4xx/5xx) as well as success responses.
func TestSecurityHeaders_HeadersSetBeforeInnerHandler(t *testing.T) {
	statusCodes := []int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusMethodNotAllowed,
		http.StatusInternalServerError,
	}

	for _, code := range statusCodes {
		code := code // capture range variable
		t.Run(http.StatusText(code), func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			})

			handler := SecurityHeaders(inner)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			csp := rr.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Errorf("status %d: Content-Security-Policy header is missing", code)
			}
		})
	}
}

// TestSecurityHeaders_MultipleRequests verifies that the middleware correctly
// sets headers on every individual request, not just the first one.
func TestSecurityHeaders_MultipleRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		csp := rr.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Errorf("request %d: Content-Security-Policy header is missing", i+1)
		}
	}
}
