package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/service"
)

// TestSetSecurityHeaders verifies that setSecurityHeaders writes all required
// security headers (Content-Security-Policy, X-Content-Type-Options,
// X-Frame-Options) onto the response writer. This is the primary regression
// test for the CWE-346 / Missing Content Security Policy remediation.
func TestSetSecurityHeaders(t *testing.T) {
	rr := httptest.NewRecorder()
	setSecurityHeaders(rr)

	tests := []struct {
		header string
		want   string
	}{
		{
			header: "Content-Security-Policy",
			want:   contentSecurityPolicy,
		},
		{
			header: "X-Content-Type-Options",
			want:   "nosniff",
		},
		{
			header: "X-Frame-Options",
			want:   "DENY",
		},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			got := rr.Header().Get(tc.header)
			if got != tc.want {
				t.Errorf("header %q = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestContentSecurityPolicyValue verifies that the CSP constant restricts
// resources to same-origin, blocks framing, and disables dangerous object
// embedding.
func TestContentSecurityPolicyValue(t *testing.T) {
	requiredDirectives := []string{
		"default-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
	}

	for _, directive := range requiredDirectives {
		t.Run(directive, func(t *testing.T) {
			if !strings.Contains(contentSecurityPolicy, directive) {
				t.Errorf(
					"contentSecurityPolicy missing directive %q; got: %q",
					directive, contentSecurityPolicy,
				)
			}
		})
	}
}

// TestCreateRepoCSPHeader verifies that the /api/repo/create handler sets
// the Content-Security-Policy header even when the request is rejected early
// (method not allowed), confirming the header is applied before any branching.
func TestCreateRepoCSPHeader(t *testing.T) {
	h := &Handler{
		// repoStore, validator and gitService are nil — the handler must reach
		// the method-not-allowed branch before using them.
	}

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing on CreateRepo response")
	}
	if csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

// TestCloneRepoCSPHeader verifies that the CloneRepo handler sets the
// Content-Security-Policy header on early-exit (method not allowed) responses.
func TestCloneRepoCSPHeader(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodGet, "/api/repo/clone", nil)
	rr := httptest.NewRecorder()

	h.CloneRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing on CloneRepo response")
	}
	if csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

// TestListReposCSPHeader verifies that the ListRepos handler sets the
// Content-Security-Policy header on early-exit (method not allowed) responses.
func TestListReposCSPHeader(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	rr := httptest.NewRecorder()

	h.ListRepos(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rr.Code)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header is missing on ListRepos response")
	}
	if csp != contentSecurityPolicy {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, contentSecurityPolicy)
	}
}

// TestXFrameOptionsOnAllHandlers verifies that all handlers set X-Frame-Options
// to DENY, preventing clickjacking attacks.
func TestXFrameOptionsOnAllHandlers(t *testing.T) {
	h := &Handler{}

	handlers := []struct {
		name    string
		method  string
		path    string
		fn      func(http.ResponseWriter, *http.Request)
	}{
		{"CreateRepo", http.MethodGet, "/api/repo/create", h.CreateRepo},
		{"CloneRepo", http.MethodGet, "/api/repo/clone", h.CloneRepo},
		{"ListRepos", http.MethodPost, "/api/repo/list", h.ListRepos},
	}

	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()

			tc.fn(rr, req)

			got := rr.Header().Get("X-Frame-Options")
			if got != "DENY" {
				t.Errorf("%s: X-Frame-Options = %q, want %q", tc.name, got, "DENY")
			}
		})
	}
}

// TestXContentTypeOptionsOnAllHandlers verifies that all handlers set
// X-Content-Type-Options to "nosniff", preventing MIME-sniffing attacks.
func TestXContentTypeOptionsOnAllHandlers(t *testing.T) {
	h := &Handler{}

	handlers := []struct {
		name   string
		method string
		path   string
		fn     func(http.ResponseWriter, *http.Request)
	}{
		{"CreateRepo", http.MethodGet, "/api/repo/create", h.CreateRepo},
		{"CloneRepo", http.MethodGet, "/api/repo/clone", h.CloneRepo},
		{"ListRepos", http.MethodPost, "/api/repo/list", h.ListRepos},
	}

	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()

			tc.fn(rr, req)

			got := rr.Header().Get("X-Content-Type-Options")
			if got != "nosniff" {
				t.Errorf("%s: X-Content-Type-Options = %q, want %q", tc.name, got, "nosniff")
			}
		})
	}
}

// captureLogOutput redirects the default logger to a buffer for the duration
// of fn, then restores the original output and returns the captured bytes.
// Any panic from fn (e.g. nil pointer on repoStore after the log sink) is
// recovered so that assertions on already-written log lines can still run.
func captureLogOutput(fn func()) (out string) {
	var buf bytes.Buffer
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0) // suppress timestamps so assertions are deterministic
	defer func() {
		recover()             // absorb nil-repoStore panic that may occur after the log line
		out = buf.String()    // capture whatever was written before the panic
		log.SetOutput(os.Stderr)
		log.SetFlags(origFlags)
	}()
	fn()
	return buf.String()
}

// TestCreateRepoLogForgingNewline verifies that a git_url containing an
// embedded newline (\n) cannot inject a forged log line.
//
// Before the fix the format verb was %s, which would let the newline in
// gitURL start a new line in the log, making it look like a separate log
// entry (CWE-117 / Log Forging). After the fix the verb is %q, which quotes
// the value and renders \n as the two-character escape sequence \\n.
func TestCreateRepoLogForgingNewline(t *testing.T) {
	validator := service.NewDomainValidator()
	h := &Handler{validator: validator}

	// Craft a git_url that contains github.com (passes whitelist) but also
	// embeds a newline + fake log entry that an attacker hopes to forge.
	maliciousURL := "https://github.com/user/repo\n[AUDIT] Admin login succeeded"

	form := url.Values{}
	form.Set("name", "myrepo")
	form.Set("git_url", maliciousURL)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	captured := captureLogOutput(func() {
		h.CreateRepo(rr, req)
	})

	// The forged string must NOT appear as a standalone line in the log output.
	if strings.Contains(captured, "[AUDIT] Admin login succeeded") {
		t.Errorf("log forging succeeded: forged entry appeared verbatim in log output.\nCaptured:\n%s", captured)
	}

	// The literal newline character must NOT appear inside the logged git_url
	// value. %q turns \n into the two-byte sequence backslash+n.
	lines := strings.Split(captured, "\n")
	for _, line := range lines {
		if strings.Contains(line, "[VALIDATION] Domain validated successfully") {
			if strings.Contains(line, "\n") {
				t.Errorf("log line for domain validation still contains a raw newline: %q", line)
			}
			// Confirm the value is quoted (starts with double-quote after the colon+space).
			if !strings.Contains(line, `"https://github.com/user/repo`) {
				t.Errorf("logged git_url does not appear to be quoted; line: %q", line)
			}
		}
	}
}

// TestCreateRepoLogForgingCarriageReturn verifies that a git_url containing a
// carriage return (\r) cannot be used to overwrite a log line (terminal
// carriage-return attack).
func TestCreateRepoLogForgingCarriageReturn(t *testing.T) {
	validator := service.NewDomainValidator()
	h := &Handler{validator: validator}

	maliciousURL := "https://github.com/user/repo\r[FAKE] entry"

	form := url.Values{}
	form.Set("name", "myrepo")
	form.Set("git_url", maliciousURL)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	captured := captureLogOutput(func() {
		h.CreateRepo(rr, req)
	})

	// A raw carriage return must not appear in the captured log for the
	// validation success line.
	if strings.Contains(captured, "\r") {
		t.Errorf("raw carriage return present in log output — CR injection possible.\nCaptured: %q", captured)
	}
}

// TestCreateRepoLogForgingCleanURL verifies that a well-formed, non-malicious
// git_url is still logged correctly (no regression).
func TestCreateRepoLogForgingCleanURL(t *testing.T) {
	validator := service.NewDomainValidator()
	h := &Handler{validator: validator}

	cleanURL := "https://github.com/user/repo"

	form := url.Values{}
	form.Set("name", "myrepo")
	form.Set("git_url", cleanURL)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	captured := captureLogOutput(func() {
		h.CreateRepo(rr, req)
	})

	// The validation-success message must still be emitted.
	if !strings.Contains(captured, "[VALIDATION] Domain validated successfully") {
		t.Errorf("validation success log line missing for clean URL.\nCaptured: %q", captured)
	}

	// The URL itself must appear (quoted) inside the log output.
	if !strings.Contains(captured, cleanURL) {
		t.Errorf("clean URL %q not found in log output.\nCaptured: %q", cleanURL, captured)
	}
}
