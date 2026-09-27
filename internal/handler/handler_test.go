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

// newTestHandlerForValidation constructs a Handler with only the validator wired up.
// repoStore and gitService are nil because the tests below only exercise code paths
// that return before reaching those dependencies (validation rejection).
func newTestHandlerForValidation() *Handler {
	return &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}
}

// captureLog redirects the default logger output to a buffer for the duration of fn,
// then restores it and returns what was written.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil) // restore default (stderr)
	fn()
	return buf.String()
}

// buildCreateRequest builds a POST form request for the CreateRepo handler.
func buildCreateRequest(name, gitURL, repoType string) *http.Request {
	form := url.Values{}
	form.Set("name", name)
	form.Set("git_url", gitURL)
	if repoType != "" {
		form.Set("repo_type", repoType)
	}
	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// --- Log-Forging prevention tests ---

// TestCreateRepo_NonWhitelistedDomain_LogDoesNotContainRawNewline verifies that
// when a user supplies a git_url containing a newline (a classic CRLF log-forging
// payload), the rejection log line does NOT embed a raw newline inside the URL value.
// Using %q in log.Printf ensures the newline is rendered as the escape sequence \n
// rather than an actual line break, preventing an attacker from forging extra log lines.
func TestCreateRepo_NonWhitelistedDomain_LogDoesNotContainRawNewline(t *testing.T) {
	h := newTestHandlerForValidation()

	// Craft a URL that embeds a CRLF — the classic log-forging payload.
	maliciousURL := "http://evil.example.com\r\n[FAKE] Admin logged in"

	req := buildCreateRequest("testrepo", maliciousURL, "")
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	// The HTTP response must be 400 Bad Request.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	// The injected forged log prefix must not appear as a separate line in the output.
	if strings.Contains(logOutput, "[FAKE] Admin logged in") {
		t.Error("injected forged log line appears verbatim in log output — log forging is possible")
	}

	// The raw CR+LF sequence from user input must not be present unescaped.
	if strings.Contains(logOutput, "\r\n[FAKE]") {
		t.Error("log output contains raw CRLF from user input — log forging is possible")
	}
}

// TestCreateRepo_NonWhitelistedDomain_LogContainsEscapedURL verifies that the
// rejection log entry captures the URL in a safe, quoted form using %q.
func TestCreateRepo_NonWhitelistedDomain_LogContainsEscapedURL(t *testing.T) {
	h := newTestHandlerForValidation()

	maliciousURL := "http://evil.example.com\nINJECTED"
	req := buildCreateRequest("testrepo", maliciousURL, "")
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	// The log must contain the VALIDATION rejection marker.
	if !strings.Contains(logOutput, "[VALIDATION] Rejected non-whitelisted domain:") {
		t.Error("expected rejection log message not found")
	}

	// The URL should appear quoted (Go's %q wraps it in double-quotes).
	if !strings.Contains(logOutput, `"http://evil.example.com`) {
		t.Error("expected quoted URL in log output not found")
	}

	// The raw newline from the payload must not appear in the log.
	if strings.Contains(logOutput, "\nINJECTED") {
		t.Error("raw newline injection still present in log output")
	}
}

// TestCreateRepo_NonWhitelistedDomain_ReturnsCorrectStatusAndBody checks that the
// HTTP-level response for a non-whitelisted URL is correct and unchanged by the fix.
func TestCreateRepo_NonWhitelistedDomain_ReturnsCorrectStatusAndBody(t *testing.T) {
	h := newTestHandlerForValidation()

	req := buildCreateRequest("myrepo", "http://bitbucket.org/user/repo.git", "")
	rr := httptest.NewRecorder()

	captureLog(func() {
		h.CreateRepo(rr, req)
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "whitelisted") {
		t.Errorf("expected whitelist error message in body, got: %s", body)
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields return 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := newTestHandlerForValidation()

	form := url.Values{}
	form.Set("name", "testrepo")
	// Omit git_url intentionally
	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing fields, got %d", rr.Code)
	}
}

// TestCreateRepo_WrongMethod verifies that non-POST requests are rejected.
func TestCreateRepo_WrongMethod(t *testing.T) {
	h := newTestHandlerForValidation()

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

// TestCreateRepo_LogForging_TabInjection verifies that tab characters in user
// input are safely escaped in log output when using %q.
func TestCreateRepo_LogForging_TabInjection(t *testing.T) {
	h := newTestHandlerForValidation()

	tabURL := "http://evil.example.com\t[FAKE_FIELD]=value"
	req := buildCreateRequest("testrepo", tabURL, "")
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	// A raw tab inside the URL must not appear unescaped; %q renders \t as \\t.
	if strings.Contains(logOutput, "\t[FAKE_FIELD]") {
		t.Error("raw tab from user input appears unescaped in log output — potential log forging")
	}
}

// TestCreateRepo_LogForging_NullByteInjection verifies that a null byte in user input
// is safely escaped.  The null byte is written using the \x00 hex escape in the source
// (never as a literal NUL byte) so the file remains valid UTF-8 text.
func TestCreateRepo_LogForging_NullByteInjection(t *testing.T) {
	h := newTestHandlerForValidation()

	nullURL := "http://evil.example.com\x00hidden"
	req := buildCreateRequest("testrepo", nullURL, "")
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	// The raw NUL byte (\x00) must not appear unescaped in the log output.
	if strings.Contains(logOutput, "\x00") {
		t.Error("raw null byte from user input appears in log output")
	}
}
