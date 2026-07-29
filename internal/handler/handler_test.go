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

// logCapture captures log output during a test so we can assert on it.
type logCapture struct {
	buf *bytes.Buffer
}

func newLogCapture() *logCapture {
	lc := &logCapture{buf: &bytes.Buffer{}}
	log.SetOutput(lc.buf)
	log.SetFlags(0) // strip date/time prefix so assertions are deterministic
	return lc
}

func (lc *logCapture) output() string {
	return lc.buf.String()
}

// restore resets the log output to the default after the test.
func (lc *logCapture) restore() {
	log.SetOutput(nil) // nil → os.Stderr (default)
	log.SetFlags(log.LstdFlags)
}

// --- helpers ----------------------------------------------------------

// newTestHandler builds a Handler backed only by the real DomainValidator
// (no database, no git service). Sufficient for testing CreateRepo validation
// and log-forging scenarios that do not reach the DB.
func newTestHandler() *Handler {
	return &Handler{
		validator: service.NewDomainValidator(),
		// repoStore and gitService left nil; tests that would exercise them
		// must use a proper stub or skip before reaching those code paths.
	}
}

// postForm submits a POST request with the given form values to the handler
// and returns the recorder.
func postForm(h *Handler, values url.Values) *httptest.ResponseRecorder {
	body := strings.NewReader(values.Encode())
	req := httptest.NewRequest(http.MethodPost, "/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// --- Log-Forging regression tests -------------------------------------

// TestCreateRepo_LogForging_NewlineInjection verifies that a gitURL containing
// a newline (the classic log-forging payload) does NOT appear as a literal
// newline in the log output. The %q format verb used in the fix will escape
// \n to `\n` (two printable characters), preventing an attacker from injecting
// fake log lines.
func TestCreateRepo_LogForging_NewlineInjection(t *testing.T) {
	lc := newLogCapture()
	defer lc.restore()

	h := newTestHandler()

	// Craft a gitURL that belongs to a whitelisted domain but embeds a newline
	// followed by a forged log entry. The URL passes the domain whitelist check
	// so execution reaches the audit log at the fixed line.
	maliciousURL := "https://github.com/user/repo\n[SECURITY] admin logged in as root"

	values := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}
	postForm(h, values)

	logOutput := lc.output()

	// The raw newline must NOT appear in the log output.
	if strings.Contains(logOutput, "\n[SECURITY]") {
		t.Errorf("Log forging: raw newline and forged entry found in log output.\nGot: %s", logOutput)
	}

	// The %q verb must have escaped the newline to the two-character sequence \n.
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("Expected escaped newline (\\n) in log output to confirm %q quoting is active.\nGot: %s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInjection verifies that a carriage
// return in the gitURL is also escaped rather than emitted literally.
func TestCreateRepo_LogForging_CarriageReturnInjection(t *testing.T) {
	lc := newLogCapture()
	defer lc.restore()

	h := newTestHandler()

	maliciousURL := "https://github.com/user/repo\r[FAKE] injected entry"
	values := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}
	postForm(h, values)

	logOutput := lc.output()

	if strings.Contains(logOutput, "\r[FAKE]") {
		t.Errorf("Log forging: raw carriage-return and forged entry found in log output.\nGot: %s", logOutput)
	}
}

// TestCreateRepo_LogForging_TabInjection verifies that a tab character in the
// gitURL is quoted (escaped to \t) rather than emitted as a raw tab.
func TestCreateRepo_LogForging_TabInjection(t *testing.T) {
	lc := newLogCapture()
	defer lc.restore()

	h := newTestHandler()

	// URL with tab followed by text that could look like a structured field
	maliciousURL := "https://github.com/user/repo\t[injected_field]=value"
	values := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}
	postForm(h, values)

	logOutput := lc.output()

	// Raw tab should not appear in the log message; it should be escaped.
	if strings.Contains(logOutput, "\t[injected_field]") {
		t.Errorf("Log forging: raw tab and injected field found in log output.\nGot: %s", logOutput)
	}
}

// TestCreateRepo_LogForging_ValidURL verifies that a clean, whitelisted URL
// is still logged (the fix must not suppress legitimate audit entries) and that
// the log message contains the expected prefix and the URL in quoted form.
// Note: this test does NOT reach the DB (repoStore is nil), so we only check
// up to the validation log line; the handler will panic when it tries to call
// repoStore.Create. We use a recover to handle that gracefully.
func TestCreateRepo_LogForging_ValidURL(t *testing.T) {
	lc := newLogCapture()
	defer lc.restore()

	h := newTestHandler()

	safeURL := "https://github.com/user/myrepo"
	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {safeURL},
	}

	// The handler will panic after the log line when repoStore is nil.
	// Catch the panic so we can still inspect the log output.
	func() {
		defer func() { recover() }() //nolint:errcheck
		postForm(h, values)
	}()

	logOutput := lc.output()

	// The validation success line must be present.
	if !strings.Contains(logOutput, "[VALIDATION] Domain validated successfully:") {
		t.Errorf("Expected validation success log line.\nGot: %s", logOutput)
	}

	// The URL must appear quoted (surrounded by double-quotes as produced by %q).
	expectedQuoted := `"` + safeURL + `"`
	if !strings.Contains(logOutput, expectedQuoted) {
		t.Errorf("Expected quoted URL %s in log output.\nGot: %s", expectedQuoted, logOutput)
	}
}

// --- Existing-functionality (non-security) tests ----------------------

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields verifies that requests without name or git_url
// are rejected with 400 Bad Request.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := newTestHandler()

	tests := []struct {
		name   string
		values url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/u/r"}}},
		{"missing git_url", url.Values{"name": {"repo"}}},
		{"missing both", url.Values{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := postForm(h, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s: expected 400, got %d", tc.name, rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that URLs from domains not on
// the allowlist are rejected with 400 Bad Request.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler()

	values := url.Values{
		"name":    {"evil-repo"},
		"git_url": {"https://evil.example.com/attacker/repo"},
	}
	rr := postForm(h, values)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for non-whitelisted domain, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "whitelisted") {
		t.Errorf("Expected 'whitelisted' in error body, got: %s", body)
	}
}
