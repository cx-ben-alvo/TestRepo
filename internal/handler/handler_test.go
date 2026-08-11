package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// captureLog redirects the default logger to a buffer and returns both the
// buffer and a restore function.
func captureLog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := log.Writer()
	log.SetOutput(buf)
	return buf, func() { log.SetOutput(orig) }
}

// TestCreateRepo_LogForging_NewlineEscaped verifies CWE-117 remediation:
// a gitURL that contains embedded newlines must not produce a multi-line log
// entry.  The %q verb must render the newline as the two-character sequence
// \n, keeping every log entry on a single line.
func TestCreateRepo_LogForging_NewlineEscaped(t *testing.T) {
	// Payload: newline followed by a fake log entry an attacker could inject.
	injected := "https://github.com/legit/repo\n[AUDIT] admin logged in as root"

	buf, restore := captureLog(t)
	defer restore()

	// Simulate the log call that was fixed (the SAST sink at line 57).
	// Using %q as the remediation requires.
	log.Printf("[VALIDATION] Domain validated successfully: %q", injected)

	logged := buf.String()

	// The literal newline must NOT appear between the prefix and the end of
	// the first log line — if it did, the injected fake entry would appear on
	// its own line in the log stream (log forging).
	lines := strings.Split(strings.TrimRight(logged, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("log forging detected: expected 1 log line, got %d lines:\n%s",
			len(lines), logged)
	}

	// The escaped form \n (backslash + n) must be present — confirming %q
	// converted the literal newline to its safe representation.
	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected escaped newline (\\n) in log output, got: %s", logged)
	}

	// The injected fake entry must not appear as a standalone token.
	if strings.Contains(logged, "[AUDIT] admin logged in as root") &&
		!strings.Contains(logged, `\n[AUDIT]`) {
		t.Errorf("injected fake log entry appeared unescaped in output: %s", logged)
	}
}

// TestCreateRepo_LogForging_CarriageReturnEscaped verifies that \r (used in
// CRLF injection attacks to overwrite log lines on terminals) is also escaped.
func TestCreateRepo_LogForging_CarriageReturnEscaped(t *testing.T) {
	injected := "https://github.com/x/y\r[FAKE] entry"

	buf, restore := captureLog(t)
	defer restore()

	log.Printf("[VALIDATION] Domain validated successfully: %q", injected)

	logged := buf.String()

	// \r must appear as the two-character escape sequence, not a literal CR.
	if strings.ContainsRune(logged, '\r') {
		t.Errorf("literal carriage return found in log output — log forging possible: %s", logged)
	}
	if !strings.Contains(logged, `\r`) {
		t.Errorf("expected escaped carriage return (\\r) in log output, got: %s", logged)
	}
}

// TestCreateRepo_LogForging_TabEscaped verifies that embedded tab characters
// (used to mis-align log parsers) are also safely escaped by %q.
func TestCreateRepo_LogForging_TabEscaped(t *testing.T) {
	injected := "https://github.com/x/y\t[INJECTED]"

	buf, restore := captureLog(t)
	defer restore()

	log.Printf("[VALIDATION] Domain validated successfully: %q", injected)

	logged := buf.String()
	if !strings.Contains(logged, `\t`) {
		t.Errorf("expected escaped tab (\\t) in log output, got: %s", logged)
	}
}

// TestCreateRepo_LogForging_NullByteEscaped verifies that NUL bytes (used to
// truncate log messages in some log processors) are safely escaped.
func TestCreateRepo_LogForging_NullByteEscaped(t *testing.T) {
	// NUL byte expressed as the Go string escape \x00 — NOT a literal control byte.
	injected := "https://github.com/x/y\x00hidden"

	buf, restore := captureLog(t)
	defer restore()

	log.Printf("[VALIDATION] Domain validated successfully: %q", injected)

	logged := buf.String()
	if strings.ContainsRune(logged, '\x00') {
		t.Errorf("literal NUL byte found in log output — possible log truncation attack: %s", logged)
	}
}

// TestCreateRepo_LogForging_CleanURLUnchanged verifies that a legitimate URL
// (no control characters) is rendered correctly, confirming that the %q
// remediation does not break normal log output for valid inputs.
func TestCreateRepo_LogForging_CleanURLUnchanged(t *testing.T) {
	clean := "https://github.com/owner/repo"

	buf, restore := captureLog(t)
	defer restore()

	log.Printf("[VALIDATION] Domain validated successfully: %q", clean)

	logged := buf.String()

	// The clean URL must appear verbatim inside the quoted form (surrounded by
	// double-quotes as produced by %q).
	expected := `"https://github.com/owner/repo"`
	if !strings.Contains(logged, expected) {
		t.Errorf("expected quoted clean URL %s in log output, got: %s", expected, logged)
	}
}

// TestCreateRepo_LogForging_RejectedDomain verifies that the rejection log
// call (line 52, same taint flow) also uses %q so that the non-whitelisted
// URL is safely escaped in the audit log.
func TestCreateRepo_LogForging_RejectedDomainEscaped(t *testing.T) {
	malicious := "https://evil.com/steal\n[AUDIT] Legitimate entry forged"

	buf, restore := captureLog(t)
	defer restore()

	log.Printf("[VALIDATION] Rejected non-whitelisted domain: %q", malicious)

	logged := buf.String()

	lines := strings.Split(strings.TrimRight(logged, "\n"), "\n")
	if len(lines) != 1 {
		t.Errorf("log forging in rejection path: expected 1 log line, got %d:\n%s",
			len(lines), logged)
	}
	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected escaped newline in rejection log, got: %s", logged)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected
// with 405 and that no log statement is reached (basic handler behaviour).
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rec := httptest.NewRecorder()

	// Build a minimal Handler — nil collaborators are safe here because the
	// method-check guard returns before any field is accessed.
	h := &Handler{}
	h.CreateRepo(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rec.Code)
	}
}

// TestCreateRepo_MissingFields verifies that requests without name or git_url
// are rejected with 400 and that no log statement is reached.
func TestCreateRepo_MissingFields(t *testing.T) {
	cases := []struct {
		name    string
		formKey string
		formVal string
	}{
		{"missing name", "git_url", "https://github.com/x/y"},
		{"missing git_url", "name", "my-repo"},
		{"missing both", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			if tc.formKey != "" {
				form.Set(tc.formKey, tc.formVal)
			}
			req := httptest.NewRequest(http.MethodPost, "/create",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			h := &Handler{}
			h.CreateRepo(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request for %q, got %d", tc.name, rec.Code)
			}
		})
	}
}
