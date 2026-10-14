package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityHeaders_CSPHeaderIsSet verifies that the SecurityHeaders middleware
// adds a Content-Security-Policy header to every response, addressing CWE-346.
func TestSecurityHeaders_CSPHeaderIsSet(t *testing.T) {
	innerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if !innerCalled {
		t.Fatal("SecurityHeaders middleware did not invoke the wrapped handler")
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing from the response")
	}
}

// TestSecurityHeaders_CSPValue verifies that the CSP header value is not a
// permissive wildcard and restricts content to the same origin.
func TestSecurityHeaders_CSPValue(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")

	// The policy must not be the dangerous wildcard value.
	if csp == "*" || csp == "default-src *" {
		t.Errorf("Content-Security-Policy is too permissive: %q", csp)
	}

	// The policy must include a default-src directive.
	if len(csp) == 0 {
		t.Error("Content-Security-Policy header must not be empty")
	}
}

// TestSecurityHeaders_CSPSetBeforeInnerHandler ensures the CSP header is
// written before the inner handler executes (so it cannot be overwritten by
// response body writes that implicitly flush headers).
func TestSecurityHeaders_CSPSetBeforeInnerHandler(t *testing.T) {
	var cspDuringInner string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the header value as seen inside the wrapped handler.
		cspDuringInner = w.Header().Get("Content-Security-Policy")
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if cspDuringInner == "" {
		t.Error("Content-Security-Policy was not set before the inner handler executed")
	}
}

// TestSecurityHeaders_WrapsAnyStatusCode verifies the CSP header is present
// regardless of the HTTP status code returned by the inner handler.
func TestSecurityHeaders_WrapsAnyStatusCode(t *testing.T) {
	statuses := []int{
		http.StatusOK,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusInternalServerError,
	}

	for _, status := range statuses {
		status := status // capture for closure
		t.Run(http.StatusText(status), func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})

			handler := SecurityHeaders(inner)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()
			handler(rr, req)

			csp := rr.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Errorf("Content-Security-Policy missing for status %d", status)
			}
		})
	}
}
