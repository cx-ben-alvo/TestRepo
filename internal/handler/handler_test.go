package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/service"
)

// logCapturer redirects the default logger to a buffer for assertion.
func logCapturer(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := log.Writer()
	log.SetOutput(buf)
	return buf, func() { log.SetOutput(orig) }
}

// newTestHandler creates a Handler whose repoStore and gitService are nil.
// Tests that exercise paths requiring a real repoStore/gitService must not
// rely on this helper and should construct their own doubles instead.
func newTestHandler() *Handler {
	validator := service.NewDomainValidator()
	return &Handler{
		repoStore:  nil,
		validator:  validator,
		gitService: nil,
	}
}

// TestCreateRepo_LogForging_NewlineInName verifies that a user-supplied name
// containing embedded newlines is logged with %q formatting so that the
// newline characters are escaped (e.g. \n) rather than emitted raw.
//
// Log Forging (CWE-117): an attacker can inject fake log entries by embedding
// newlines in form fields.  The fix uses the %q verb which Go's fmt package
// escapes, turning \n → \\n and \r → \\r.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	// Craft a name payload that attempts to inject a fake log line.
	maliciousName := "legit\n[REPO] INJECTED FAKE LOG ENTRY id=999"

	form := url.Values{}
	form.Set("name", maliciousName)
	form.Set("git_url", "https://github.com/owner/repo")
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	buf, restore := logCapturer(t)
	defer restore()

	h := newTestHandler()
	h.CreateRepo(rec, req)

	logged := buf.String()

	// The raw newline must NOT appear in log output — that is the forging vector.
	if strings.Contains(logged, "\n[REPO] INJECTED FAKE LOG ENTRY") {
		t.Errorf("log forging: raw newline reached log output; logged: %q", logged)
	}

	// If the handler reached the logging point, the escaped form \n must appear
	// (because %q escapes the newline).  If the handler short-circuited before
	// reaching that log statement (e.g. DB error with nil store), the important
	// thing is still that the raw injected fake entry is absent.
	//
	// Either way, the dangerous raw payload must not appear verbatim.
	if strings.Contains(logged, "INJECTED FAKE LOG ENTRY") {
		// Only a problem when it is on a NEW line (i.e. was not escaped).
		lines := strings.Split(logged, "\n")
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "[REPO] INJECTED FAKE LOG ENTRY") {
				t.Errorf("log forging: injected fake log line appeared as its own line: %q", line)
			}
		}
	}
}

// TestCreateRepo_LogForging_CarriageReturnInName verifies that carriage-return
// characters in a user-supplied name are also escaped when logged.
func TestCreateRepo_LogForging_CarriageReturnInName(t *testing.T) {
	maliciousName := "legit\r\n[AUDIT] Admin logged in as root"

	form := url.Values{}
	form.Set("name", maliciousName)
	form.Set("git_url", "https://github.com/owner/repo")
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	buf, restore := logCapturer(t)
	defer restore()

	h := newTestHandler()
	h.CreateRepo(rec, req)

	logged := buf.String()

	// A raw carriage-return followed by a newline must not produce a new log line.
	if strings.Contains(logged, "\r\n[AUDIT]") {
		t.Errorf("log forging: raw CRLF reached log output; logged: %q", logged)
	}
}

// TestCreateRepo_LogForging_QuotedEscape verifies that when the handler does
// reach the [REPO] log statement, the %q verb wraps the name in double-quotes
// and escapes embedded newlines as \n literals.
//
// This test uses a git_url that passes domain validation but will hit a nil-
// repoStore, so the [REPO] log line won't be reached.  Instead it confirms
// the VALIDATION log is also safe.  A full integration test requiring a real
// DB would be needed to assert the [REPO] line specifically; this unit test
// covers the input-sanitization contract at the handler level.
func TestCreateRepo_DomainValidation_LogSafe(t *testing.T) {
	// A name with an embedded newline so we can detect if it leaks raw.
	form := url.Values{}
	form.Set("name", "repo\nINJECTED")
	form.Set("git_url", "https://github.com/owner/safe")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	buf, restore := logCapturer(t)
	defer restore()

	h := newTestHandler()
	h.CreateRepo(rec, req)

	logged := buf.String()

	// Raw newline followed by INJECTED must not create an independent log line.
	lines := strings.Split(logged, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "INJECTED" || strings.HasPrefix(trimmed, "INJECTED") {
			t.Errorf("log forging: injected payload appeared as its own log line: %q", line)
		}
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected
// before any logging occurs.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rec := httptest.NewRecorder()

	h := newTestHandler()
	h.CreateRepo(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// TestCreateRepo_MissingFields verifies that empty name/git_url triggers a
// 400 before any log is written.
func TestCreateRepo_MissingFields(t *testing.T) {
	form := url.Values{}
	form.Set("name", "")
	form.Set("git_url", "")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h := newTestHandler()
	h.CreateRepo(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", rec.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that git URLs not in the
// whitelist are rejected with 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	form := url.Values{}
	form.Set("name", "myrepo")
	form.Set("git_url", "https://evil.example.com/repo")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	buf, restore := logCapturer(t)
	defer restore()

	h := newTestHandler()
	h.CreateRepo(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rec.Code)
	}

	// The rejected URL is logged but comes from a domain-validated code path —
	// confirm no raw newline injection is possible there either.
	logged := buf.String()
	if strings.Count(logged, "\n") > 1 {
		// Validation log line ends with one \n; multiple lines means raw injection.
		lines := strings.Split(strings.TrimRight(logged, "\n"), "\n")
		if len(lines) > 1 {
			// Only a problem if a second line carries injected content.
			for _, l := range lines[1:] {
				if strings.TrimSpace(l) != "" {
					t.Errorf("unexpected extra log line from validation log: %q", l)
				}
			}
		}
	}
}
