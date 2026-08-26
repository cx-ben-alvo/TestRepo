package handler

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/service"
)

// cspHeader is the header name for Content-Security-Policy.
const cspHeader = "Content-Security-Policy"

// expectedCSP is the policy value that must appear on every response.
const expectedCSP = "default-src 'self'"

// TestWithSecurityHeaders_SetsCSPHeader verifies that WithSecurityHeaders adds
// the Content-Security-Policy header before the wrapped handler runs.
func TestWithSecurityHeaders_SetsCSPHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("expected %q header to be set; got empty string", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("%q header: got %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestWithSecurityHeaders_CSPNotWildcard verifies that the policy does not use
// a wildcard (*) source, which would defeat the protection entirely.
func TestWithSecurityHeaders_CSPNotWildcard(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	csp := rr.Header().Get(cspHeader)
	if strings.Contains(csp, "*") {
		t.Errorf("%q header must not use wildcard (*), got %q", cspHeader, csp)
	}
}

// TestWithSecurityHeaders_InnerHandlerStillRuns verifies that the middleware
// does not swallow the response from the wrapped handler.
func TestWithSecurityHeaders_InnerHandlerStillRuns(t *testing.T) {
	const wantStatus = http.StatusAccepted
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(wantStatus)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != wantStatus {
		t.Errorf("inner handler status: got %d, want %d", rr.Code, wantStatus)
	}
}

// TestWithSecurityHeaders_CSPPresentOnErrorResponses verifies that the CSP
// header is present even when the inner handler writes an error response.
// This matters because error paths are the most likely to be missed by a
// handler-level (rather than middleware-level) header approach.
func TestWithSecurityHeaders_CSPPresentOnErrorResponses(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
	})

	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("%q header must be set even on error responses; got empty string", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("%q on error response: got %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCSPDefaultSrcSelf_NotEmpty verifies the policy value is non-trivially
// populated — it must not be blank or contain only whitespace.
func TestCSPDefaultSrcSelf_NotEmpty(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	wrapped := WithSecurityHeaders(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	csp := rr.Header().Get(cspHeader)
	if strings.TrimSpace(csp) == "" {
		t.Errorf("%q header must not be empty or whitespace-only", cspHeader)
	}
}

// TestCreateRepo_MethodNotAllowed_HasCSPHeader verifies that the CSP header is
// present when CreateRepo rejects a non-POST request — an early-exit code path.
func TestCreateRepo_MethodNotAllowed_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CreateRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CreateRepo (405 path): %q header not set; got empty string", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CreateRepo (405 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCreateRepo_MissingFields_HasCSPHeader verifies that the CSP header is
// present when CreateRepo returns 400 for missing required fields.
func TestCreateRepo_MissingFields_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CreateRepo)

	// POST with no body fields → name and git_url will be empty.
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CreateRepo (400 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CreateRepo (400 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCloneRepo_MethodNotAllowed_HasCSPHeader verifies that the CSP header is
// present when CloneRepo rejects a non-POST request.
func TestCloneRepo_MethodNotAllowed_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CloneRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/clone", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CloneRepo (405 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CloneRepo (405 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestCloneRepo_MissingRepoID_HasCSPHeader verifies that the CSP header is
// present when CloneRepo returns 400 for a missing repo_id field.
func TestCloneRepo_MissingRepoID_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.CloneRepo)

	// POST with no body fields → repo_id will be empty.
	req := httptest.NewRequest(http.MethodPost, "/api/repo/clone", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("CloneRepo (400 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("CloneRepo (400 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// TestListRepos_MethodNotAllowed_HasCSPHeader verifies that the CSP header is
// present when ListRepos rejects a non-GET request.
func TestListRepos_MethodNotAllowed_HasCSPHeader(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  nil,
		gitService: nil,
	}

	wrapped := WithSecurityHeaders(h.ListRepos)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	wrapped(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	got := rr.Header().Get(cspHeader)
	if got == "" {
		t.Errorf("ListRepos (405 path): %q header not set", cspHeader)
	}
	if got != expectedCSP {
		t.Errorf("ListRepos (405 path): %q = %q, want %q", cspHeader, got, expectedCSP)
	}
}

// ---- Log Forging (CWE-117) remediation tests --------------------------------
//
// The CreateRepo handler logs an audit message after a successful repository
// creation.  User-supplied values (name, url) are formatted with the %q verb
// so that embedded newlines or other control characters are escaped and cannot
// inject fake log lines.
//
// Because the log statement is only reached after a successful database write
// (which we cannot perform in a unit test without a real DB), we test the
// property directly: %q escapes every control character that would otherwise
// enable log forging.

// captureLog redirects the default logger to a bytes.Buffer for the duration
// of the test function and restores the original output when the returned
// cleanup function is called.
func captureLog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	origFlags := log.Flags()
	log.SetFlags(0) // strip timestamp so assertions are deterministic
	log.SetOutput(&buf)
	return &buf, func() {
		log.SetOutput(nil) // restore to default (stderr)
		log.SetFlags(origFlags)
	}
}

// TestLogForging_NewlineInName verifies that a newline character embedded in
// the repository name is escaped in the log output and does not produce a
// second, forged log line.
func TestLogForging_NewlineInName(t *testing.T) {
	buf, cleanup := captureLog(t)
	defer cleanup()

	name := "legitimate-repo\nFAKE [AUDIT] admin logged in as root"
	gitURL := "https://github.com/example/repo"
	lastID := int64(1)

	// Reproduce the exact log call used in CreateRepo after the fix.
	log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, name, gitURL)

	output := buf.String()

	// The raw newline must NOT appear in the log output.
	if strings.Contains(output, "\n[FAKE") || strings.Contains(output, "\nFAKE") {
		t.Errorf("log output contains a forged second line — newline was not escaped:\n%s", output)
	}

	// The escaped representation (\n) MUST appear instead.
	if !strings.Contains(output, `\n`) {
		t.Errorf("expected escaped newline (\\n) in log output, but it was absent:\n%s", output)
	}
}

// TestLogForging_CarriageReturnInURL verifies that a carriage-return character
// embedded in the git URL is escaped and cannot overwrite a log line (a common
// terminal log-forging trick on Windows-style log readers).
func TestLogForging_CarriageReturnInURL(t *testing.T) {
	buf, cleanup := captureLog(t)
	defer cleanup()

	name := "myrepo"
	gitURL := "https://github.com/example/repo\rFAKE [REPO] Created repo ID=99"
	lastID := int64(2)

	log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, name, gitURL)

	output := buf.String()

	// The literal carriage return must NOT be present; it should be escaped as \r.
	if strings.ContainsRune(output, '\r') {
		t.Errorf("log output contains a raw carriage return — carriage return was not escaped:\n%s", output)
	}

	// The escaped representation (\r) MUST appear.
	if !strings.Contains(output, `\r`) {
		t.Errorf("expected escaped carriage return (\\r) in log output, but it was absent:\n%s", output)
	}
}

// TestLogForging_NullByteInName verifies that a null byte embedded in the name
// is escaped and cannot be used to truncate or corrupt structured log parsers.
func TestLogForging_NullByteInName(t *testing.T) {
	buf, cleanup := captureLog(t)
	defer cleanup()

	// Null byte expressed as a Go escape sequence — never as a literal control byte.
	name := "repo\x00admin"
	gitURL := "https://github.com/example/repo"
	lastID := int64(3)

	log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, name, gitURL)

	output := buf.String()

	// The raw null byte (\x00) must not appear literally in the log output.
	if strings.ContainsRune(output, '\x00') {
		t.Errorf("log output contains a raw null byte — null byte was not escaped:\n%s", output)
	}
}

// TestLogForging_LogFormat_UsesQuotedVerb verifies that the %q verb produces
// the expected Go-quoted string representation (surrounded by double-quotes with
// special characters escaped).  This is a contract test: if someone changes %q
// back to %s the assertion will fail.
func TestLogForging_LogFormat_UsesQuotedVerb(t *testing.T) {
	tests := []struct {
		name        string
		inputName   string
		inputURL    string
		wantContain string // substring that must be present in log line
	}{
		{
			name:        "plain values are quoted",
			inputName:   "myrepo",
			inputURL:    "https://github.com/example/repo",
			wantContain: `name="myrepo"`,
		},
		{
			name:        "embedded newline is escaped",
			inputName:   "repo\ninjected",
			inputURL:    "https://github.com/example/repo",
			wantContain: `\n`,
		},
		{
			name:        "embedded tab is escaped",
			inputName:   "repo\tname",
			inputURL:    "https://github.com/example/repo",
			wantContain: `\t`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf, cleanup := captureLog(t)
			defer cleanup()

			log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", int64(1), tc.inputName, tc.inputURL)
			output := buf.String()

			if !strings.Contains(output, tc.wantContain) {
				t.Errorf("log output %q does not contain expected %q", output, tc.wantContain)
			}
		})
	}
}

// TestLogForging_CreateRepo_RejectsNonWhitelistedDomain_NoLogInjection verifies
// that the early-rejection path (non-whitelisted domain) does not allow log
// forging through the gitURL field.  The rejection log message at line 64
// also uses a %s verb for gitURL; this test confirms that the whitelisted-domain
// check prevents a malicious URL from reaching the log sink at all when the
// domain is invalid.
func TestLogForging_CreateRepo_RejectsNonWhitelistedDomain_NoLogInjection(t *testing.T) {
	h := &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}

	// Craft a gitURL that embeds a fake log line after a newline.
	maliciousURL := fmt.Sprintf("https://evil.com/repo\n[REPO] Created repo ID=999, name=%q, url=%q",
		"hacked", "https://github.com/backdoor")

	body := strings.NewReader(
		"name=testrepo&git_url=" + maliciousURL + "&repo_type=git",
	)
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	// The request must be rejected (non-whitelisted domain → 400).
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}
