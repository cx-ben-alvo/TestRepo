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

// logCaptureBuffer captures log output written during tests.
type logCaptureBuffer struct {
	buf bytes.Buffer
}

func (b *logCaptureBuffer) String() string {
	return b.buf.String()
}

// setupLogCapture redirects the global logger to a buffer and returns it.
// The caller must invoke the returned restore function when done.
func setupLogCapture() (*logCaptureBuffer, func()) {
	lcb := &logCaptureBuffer{}
	oldFlags := log.Flags()
	log.SetFlags(0) // suppress timestamps so assertions are deterministic
	log.SetOutput(&lcb.buf)
	restore := func() {
		log.SetOutput(nil)
		log.SetFlags(oldFlags)
	}
	return lcb, restore
}

// newMinimalHandler builds a Handler with a nil repoStore and gitService so
// tests that only exercise the validation path don't need a real database.
func newMinimalHandler() *Handler {
	return &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}
}

// postCreateRepo is a helper that submits a POST to /api/repo/create with the
// given form values and returns the recorded response.
func postCreateRepo(h *Handler, formValues url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", strings.NewReader(formValues.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Log-forging prevention tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineStrippedFromRejectionLog verifies that a
// git_url containing an embedded newline does NOT produce a forged log line
// when the rejection path is taken.
//
// Attack scenario: an attacker submits
//   git_url = "evil.com\n[VALIDATION] Accepted domain: evil.com"
// Without sanitization the log would contain a fake "Accepted" entry on its
// own line. With the fix the newline must be stripped.
func TestCreateRepo_LogForging_NewlineStrippedFromRejectionLog(t *testing.T) {
	lcb, restore := setupLogCapture()
	defer restore()

	h := newMinimalHandler()
	form := url.Values{
		"name":    {"myrepo"},
		"git_url": {"evil.com\n[VALIDATION] Accepted domain: evil.com"},
	}
	rr := postCreateRepo(h, form)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}

	logged := lcb.String()

	// The forged log line must NOT appear as a separate line.
	if strings.Contains(logged, "\n[VALIDATION] Accepted domain:") {
		t.Errorf("log forging not prevented: forged line present in log output:\n%s", logged)
	}

	// The newline character itself must not appear within the logged URL value.
	// Every line of the log should start with our prefix, not with attacker content.
	for _, line := range strings.Split(logged, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "[VALIDATION]") && !strings.HasPrefix(trimmed, "[REPO]") {
			t.Errorf("unexpected log line that does not start with a known prefix (possible forged entry): %q", trimmed)
		}
	}
}

// TestCreateRepo_LogForging_CarriageReturnStrippedFromRejectionLog checks that
// a carriage-return embedded in git_url is also stripped.
func TestCreateRepo_LogForging_CarriageReturnStrippedFromRejectionLog(t *testing.T) {
	lcb, restore := setupLogCapture()
	defer restore()

	h := newMinimalHandler()
	form := url.Values{
		"name":    {"myrepo"},
		"git_url": {"evil.com\r[FORGED]"},
	}
	rr := postCreateRepo(h, form)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}

	logged := lcb.String()

	if strings.Contains(logged, "\r") {
		t.Errorf("carriage return was not stripped from log output; log forging still possible:\n%q", logged)
	}
	if strings.Contains(logged, "[FORGED]") {
		t.Errorf("forged tag appeared in log output: %q", logged)
	}
}

// TestCreateRepo_LogForging_CRLFStrippedFromRejectionLog verifies that CRLF
// sequences (as used in HTTP header injection) are stripped.
func TestCreateRepo_LogForging_CRLFStrippedFromRejectionLog(t *testing.T) {
	lcb, restore := setupLogCapture()
	defer restore()

	h := newMinimalHandler()
	form := url.Values{
		"name":    {"myrepo"},
		"git_url": {"evil.com\r\n[INJECTED LOG ENTRY]"},
	}
	rr := postCreateRepo(h, form)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}

	logged := lcb.String()

	if strings.Contains(logged, "[INJECTED LOG ENTRY]") {
		t.Errorf("CRLF log injection not prevented; injected entry present:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_MultilinePayloadCollapsed ensures that a multi-line
// payload in git_url is collapsed to a single log line with no embedded
// newlines in the URL field.
func TestCreateRepo_LogForging_MultilinePayloadCollapsed(t *testing.T) {
	lcb, restore := setupLogCapture()
	defer restore()

	h := newMinimalHandler()
	payload := "attacker.com\nline2\nline3"
	form := url.Values{
		"name":    {"myrepo"},
		"git_url": {payload},
	}
	rr := postCreateRepo(h, form)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}

	logged := lcb.String()

	// The rejection log line must contain none of the injected sub-lines.
	if strings.Contains(logged, "line2") || strings.Contains(logged, "line3") {
		t.Errorf("injected lines appeared in log output; log forging not fully prevented:\n%s", logged)
	}
}

// ---------------------------------------------------------------------------
// Functional / regression tests
// ---------------------------------------------------------------------------

// TestCreateRepo_RejectsNonWhitelistedDomain ensures the handler still returns
// 400 for a non-whitelisted URL (regression guard for the validation logic).
func TestCreateRepo_RejectsNonWhitelistedDomain(t *testing.T) {
	_, restore := setupLogCapture()
	defer restore()

	h := newMinimalHandler()
	form := url.Values{
		"name":    {"myrepo"},
		"git_url": {"https://bitbucket.org/user/repo"},
	}
	rr := postCreateRepo(h, form)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "whitelisted") {
		t.Errorf("expected whitelisted-domains error message, got: %s", rr.Body.String())
	}
}

// TestCreateRepo_MissingRequiredFields checks that missing name or git_url
// returns 400 and does not log the validation rejection message.
func TestCreateRepo_MissingRequiredFields(t *testing.T) {
	lcb, restore := setupLogCapture()
	defer restore()

	h := newMinimalHandler()
	form := url.Values{
		"name": {"myrepo"},
		// git_url intentionally omitted
	}
	rr := postCreateRepo(h, form)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing git_url, got %d", rr.Code)
	}

	// The validation rejection log line should NOT be emitted for missing fields.
	if strings.Contains(lcb.String(), "[VALIDATION] Rejected") {
		t.Errorf("rejection log unexpectedly emitted for missing-field case")
	}
}

// TestCreateRepo_MethodNotAllowed verifies non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newMinimalHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

// TestCreateRepo_WhitelistedDomainDoesNotLogRejection verifies that a valid
// github.com URL does NOT trigger the rejection log line (regression guard).
// Note: because repoStore is nil this will panic/error after validation passes,
// so we only check the log was not written with "Rejected".
func TestCreateRepo_WhitelistedDomainDoesNotLogRejection(t *testing.T) {
	lcb, restore := setupLogCapture()
	defer restore()

	h := newMinimalHandler()
	form := url.Values{
		"name":    {"myrepo"},
		"git_url": {"https://github.com/user/repo"},
	}
	// The handler will likely panic or error after validation because repoStore
	// is nil; use recover to prevent the test from aborting.
	func() {
		defer func() { recover() }() //nolint:errcheck
		postCreateRepo(h, form)
	}()

	logged := lcb.String()
	if strings.Contains(logged, "[VALIDATION] Rejected") {
		t.Errorf("rejection log emitted for a whitelisted domain: %s", logged)
	}
}
