package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// assertSecurityHeader is a helper that checks that header `name` equals `want`
// in the recorded response.
func assertSecurityHeader(t *testing.T, rr *httptest.ResponseRecorder, name, want string) {
	t.Helper()
	got := rr.Header().Get(name)
	if got != want {
		t.Errorf("header %q: got %q, want %q", name, got, want)
	}
}

// noopHandler is a trivial inner handler used to verify that SecurityHeaders
// does not suppress the downstream response.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok")) //nolint:errcheck
})

// TestSecurityHeaders_CSPPresent verifies that a Content-Security-Policy header
// is set on every response, which directly addresses CWE-346.
func TestSecurityHeaders_CSPPresent(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing; CWE-346 not addressed")
	}
}

// TestSecurityHeaders_CSPValue verifies the exact CSP directive value matches
// the policy defined in the middleware.
func TestSecurityHeaders_CSPValue(t *testing.T) {
	wantCSP := "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	assertSecurityHeader(t, rr, "Content-Security-Policy", wantCSP)
}

// TestSecurityHeaders_XContentTypeOptions verifies that the X-Content-Type-Options
// header is set to "nosniff" to prevent MIME-type sniffing attacks.
func TestSecurityHeaders_XContentTypeOptions(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	assertSecurityHeader(t, rr, "X-Content-Type-Options", "nosniff")
}

// TestSecurityHeaders_XFrameOptions verifies the clickjacking-prevention header.
func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	assertSecurityHeader(t, rr, "X-Frame-Options", "DENY")
}

// TestSecurityHeaders_XXSSProtection verifies the legacy XSS-filter header.
func TestSecurityHeaders_XXSSProtection(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	assertSecurityHeader(t, rr, "X-XSS-Protection", "1; mode=block")
}

// TestSecurityHeaders_CacheControl verifies that API responses are not cached.
func TestSecurityHeaders_CacheControl(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	assertSecurityHeader(t, rr, "Cache-Control", "no-store")
}

// TestSecurityHeaders_DelegatesResponse verifies that SecurityHeaders does not
// suppress the downstream handler's status code or body.
func TestSecurityHeaders_DelegatesResponse(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created")) //nolint:errcheck
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)

	SecurityHeaders(inner).ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("downstream status code: got %d, want %d", rr.Code, http.StatusCreated)
	}
	if !strings.Contains(rr.Body.String(), "created") {
		t.Errorf("downstream body not forwarded: got %q", rr.Body.String())
	}
}

// TestSecurityHeaders_AppliedToAllMethods verifies that security headers are
// injected regardless of the HTTP method (GET, POST, OPTIONS, etc.).
func TestSecurityHeaders_AppliedToAllMethods(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodHead,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/", nil)

			SecurityHeaders(noopHandler).ServeHTTP(rr, req)

			csp := rr.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Errorf("method %s: Content-Security-Policy header is missing", method)
			}
		})
	}
}

// TestSecurityHeaders_CSPContainsSelf verifies that 'self' is present in the
// default-src directive so that same-origin resources are still permitted.
func TestSecurityHeaders_CSPContainsSelf(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'self'") {
		t.Errorf("CSP does not contain 'self': %q", csp)
	}
}

// TestSecurityHeaders_CSPBlocksUnsafeInline verifies that the policy does NOT
// allow 'unsafe-inline' (which would weaken XSS protection).
func TestSecurityHeaders_CSPBlocksUnsafeInline(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("CSP must not allow 'unsafe-inline': %q", csp)
	}
}

// TestSecurityHeaders_CSPBlocksUnsafeEval verifies that the policy does NOT
// allow 'unsafe-eval' (which would permit eval() and similar risky APIs).
func TestSecurityHeaders_CSPBlocksUnsafeEval(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("CSP must not allow 'unsafe-eval': %q", csp)
	}
}

// TestSecurityHeaders_FrameAncestorsNone verifies that the CSP includes
// frame-ancestors 'none', superseding X-Frame-Options for modern browsers.
func TestSecurityHeaders_FrameAncestorsNone(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP does not contain frame-ancestors 'none': %q", csp)
	}
}

// TestSecurityHeaders_ObjectSrcNone verifies that the CSP includes
// object-src 'none' to block Flash and other plugin-based attacks.
func TestSecurityHeaders_ObjectSrcNone(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "object-src 'none'") {
		t.Errorf("CSP does not contain object-src 'none': %q", csp)
	}
}

// TestSecurityHeaders_HSTSPresent verifies that the HTTP Strict-Transport-Security
// header is set on every response, directly addressing the Missing HSTS Header
// finding (CWE-346).
func TestSecurityHeaders_HSTSPresent(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	hsts := rr.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatal("Strict-Transport-Security header is missing; CWE-346 (Missing HSTS Header) not addressed")
	}
}

// TestSecurityHeaders_HSTSValue verifies the exact HSTS directive: max-age of
// at least one year (31 536 000 s), includeSubDomains, and preload.
func TestSecurityHeaders_HSTSValue(t *testing.T) {
	wantHSTS := "max-age=31536000; includeSubDomains; preload"

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	assertSecurityHeader(t, rr, "Strict-Transport-Security", wantHSTS)
}

// TestSecurityHeaders_HSTSMaxAge verifies that the max-age directive is present
// and non-zero so that browsers enforce HTTPS for a meaningful period.
func TestSecurityHeaders_HSTSMaxAge(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	hsts := rr.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=") {
		t.Errorf("Strict-Transport-Security does not contain max-age directive: %q", hsts)
	}
	if strings.Contains(hsts, "max-age=0") {
		t.Errorf("Strict-Transport-Security max-age must not be 0: %q", hsts)
	}
}

// TestSecurityHeaders_HSTSIncludeSubDomains verifies that the includeSubDomains
// directive is present, ensuring that subdomain connections also use HTTPS.
func TestSecurityHeaders_HSTSIncludeSubDomains(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(noopHandler).ServeHTTP(rr, req)

	hsts := rr.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("Strict-Transport-Security does not include 'includeSubDomains': %q", hsts)
	}
}

// TestSecurityHeaders_HSTSAppliedToAllMethods verifies that the HSTS header is
// injected regardless of the HTTP method used by the client.
func TestSecurityHeaders_HSTSAppliedToAllMethods(t *testing.T) {
	methods := []string{
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodHead,
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/", nil)

			SecurityHeaders(noopHandler).ServeHTTP(rr, req)

			hsts := rr.Header().Get("Strict-Transport-Security")
			if hsts == "" {
				t.Errorf("method %s: Strict-Transport-Security header is missing", method)
			}
		})
	}
}

// TestSecurityHeaders_PreservesExistingHeaders verifies that SecurityHeaders
// does not overwrite headers already set by the inner handler.
func TestSecurityHeaders_PreservesExistingHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	SecurityHeaders(inner).ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Custom-Header"); got != "custom-value" {
		t.Errorf("X-Custom-Header was altered: got %q, want %q", got, "custom-value")
	}
	// Security headers should still be present alongside the custom header.
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy was not set when custom header was present")
	}
}
