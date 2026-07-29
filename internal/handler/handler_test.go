package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeadersMiddleware_CSPHeaderPresent verifies that the middleware
// sets a Content-Security-Policy header on every response.
func TestSecurityHeadersMiddleware_CSPHeaderPresent(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy header to be set, got empty string")
	}
}

// TestSecurityHeadersMiddleware_CSPHeaderValue verifies that the CSP header
// value matches the expected restrictive policy.
func TestSecurityHeadersMiddleware_CSPHeaderValue(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")

	// Verify the policy restricts all sources to same origin by default.
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP header missing 'default-src 'self'': got %q", csp)
	}

	// Verify script sources are restricted to same origin.
	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP header missing 'script-src 'self'': got %q", csp)
	}

	// Verify object sources are disabled to prevent plugin-based attacks.
	if !strings.Contains(csp, "object-src 'none'") {
		t.Errorf("CSP header missing 'object-src 'none'': got %q", csp)
	}

	// Verify frame embedding is prohibited (clickjacking mitigation).
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP header missing 'frame-ancestors 'none'': got %q", csp)
	}
}

// TestSecurityHeadersMiddleware_XContentTypeOptions verifies that
// X-Content-Type-Options is set to 'nosniff' to prevent MIME-type sniffing.
func TestSecurityHeadersMiddleware_XContentTypeOptions(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rr, req)

	xcto := rr.Header().Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", xcto)
	}
}

// TestSecurityHeadersMiddleware_XFrameOptions verifies that X-Frame-Options
// is set to 'DENY' to prevent clickjacking.
func TestSecurityHeadersMiddleware_XFrameOptions(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rr, req)

	xfo := rr.Header().Get("X-Frame-Options")
	if xfo != "DENY" {
		t.Errorf("expected X-Frame-Options: DENY, got %q", xfo)
	}
}

// TestSecurityHeadersMiddleware_PassesThroughStatus verifies that the
// middleware does not interfere with the downstream handler's status code.
func TestSecurityHeadersMiddleware_PassesThroughStatus(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}
}

// TestSecurityHeadersMiddleware_PassesThroughBody verifies that the
// middleware does not modify the response body produced by the handler.
func TestSecurityHeadersMiddleware_PassesThroughBody(t *testing.T) {
	expectedBody := `{"success":true}`

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedBody))
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)

	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if body != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, body)
	}
}

// TestSecurityHeadersMiddleware_AppliedToAllMethods verifies that the CSP
// header is set regardless of the HTTP method used.
func TestSecurityHeadersMiddleware_AppliedToAllMethods(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodOptions,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/", nil)

			handler.ServeHTTP(rr, req)

			csp := rr.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Errorf("method %s: expected Content-Security-Policy header, got empty string", method)
			}
		})
	}
}

// TestSecurityHeadersMiddleware_ErrorResponseHasCSP verifies that error
// responses (4xx, 5xx) also carry the Content-Security-Policy header.
func TestSecurityHeadersMiddleware_ErrorResponseHasCSP(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rr.Code)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("expected Content-Security-Policy on error response, got empty string")
	}
}

// TestSecurityHeadersMiddleware_CSPConstantValue verifies that the exported
// middleware always uses the canonical policy constant and never an empty value.
func TestSecurityHeadersMiddleware_CSPConstantValue(t *testing.T) {
	if contentSecurityPolicy == "" {
		t.Fatal("contentSecurityPolicy constant must not be empty")
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeadersMiddleware(next)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp != contentSecurityPolicy {
		t.Errorf("CSP header value %q does not match constant %q", csp, contentSecurityPolicy)
	}
}
