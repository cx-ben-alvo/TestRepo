package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSecurityHeaders_ContentSecurityPolicy verifies that the SecurityHeaders
// middleware sets the Content-Security-Policy header on every response (CWE-346).
func TestSecurityHeaders_ContentSecurityPolicy(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("Content-Security-Policy")
	if got == "" {
		t.Fatal("Content-Security-Policy header is missing; all responses must include a CSP")
	}

	// The CSP must restrict sources to same-origin to mitigate XSS.
	if got != "default-src 'self'" {
		t.Errorf("unexpected Content-Security-Policy value: got %q, want %q", got, "default-src 'self'")
	}
}

// TestSecurityHeaders_XContentTypeOptions verifies the X-Content-Type-Options header
// is set to prevent MIME-sniffing attacks.
func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want %q", got, "nosniff")
	}
}

// TestSecurityHeaders_XFrameOptions verifies the X-Frame-Options header
// is set to prevent clickjacking.
func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("X-Frame-Options")
	if got != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want %q", got, "DENY")
	}
}

// TestSecurityHeaders_XXSSProtection verifies the X-XSS-Protection header is set.
func TestSecurityHeaders_XXSSProtection(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("X-XSS-Protection")
	if got != "1; mode=block" {
		t.Errorf("X-XSS-Protection: got %q, want %q", got, "1; mode=block")
	}
}

// TestSecurityHeaders_ReferrerPolicy verifies the Referrer-Policy header is set.
func TestSecurityHeaders_ReferrerPolicy(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	got := rec.Header().Get("Referrer-Policy")
	if got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy: got %q, want %q", got, "strict-origin-when-cross-origin")
	}
}

// TestSecurityHeaders_PassthroughResponse verifies the middleware forwards the
// response body and status code from the wrapped handler unchanged.
func TestSecurityHeaders_PassthroughResponse(t *testing.T) {
	const wantStatus = http.StatusCreated
	const wantBody = `{"ok":true}`

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(wantStatus)
		w.Write([]byte(wantBody)) //nolint:errcheck
	})

	handler := SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != wantStatus {
		t.Errorf("status code: got %d, want %d", rec.Code, wantStatus)
	}
	if got := rec.Body.String(); got != wantBody {
		t.Errorf("body: got %q, want %q", got, wantBody)
	}
}

// TestSecurityHeaders_AllRequiredHeadersPresent is a table-driven regression test
// that asserts every security header is present in a single request, preventing
// any individual header from being accidentally removed in the future.
func TestSecurityHeaders_AllRequiredHeadersPresent(t *testing.T) {
	requiredHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := SecurityHeaders(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	for header, wantValue := range requiredHeaders {
		t.Run(header, func(t *testing.T) {
			got := rec.Header().Get(header)
			if got == "" {
				t.Errorf("header %q is missing from the response", header)
				return
			}
			if got != wantValue {
				t.Errorf("header %q: got %q, want %q", header, got, wantValue)
			}
		})
	}
}

// TestSecurityHeaders_ErrorResponseIncludesCSP verifies that even error responses
// (4xx, 5xx) produced by the inner handler carry the security headers.
func TestSecurityHeaders_ErrorResponseIncludesCSP(t *testing.T) {
	errorStatuses := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusInternalServerError,
	}

	for _, status := range errorStatuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "error", status)
			})

			handler := SecurityHeaders(next)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Content-Security-Policy"); got == "" {
				t.Errorf("Content-Security-Policy missing on %d response", status)
			}
		})
	}
}
