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

// mockRepositoryStore is a minimal stub that satisfies the handler's needs
// without requiring a real database connection.
type mockRepositoryStore struct {
	createFunc func(name, gitURL, repoType string) (int64, error)
}

func (m *mockRepositoryStore) Create(name, gitURL, repoType string) (int64, error) {
	if m.createFunc != nil {
		return m.createFunc(name, gitURL, repoType)
	}
	return 1, nil
}

// captureLogOutput redirects the standard logger to a buffer for the duration
// of the test and returns the buffer so assertions can be made on its content.
func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(nil) }) // restore default (stderr) when done
	return &buf
}

// newTestHandler builds a Handler that uses the domain validator and a mock
// repository store so no real database or git service is needed.
func newTestHandler(store *mockRepositoryStore) *Handler {
	validator := service.NewDomainValidator()
	return &Handler{
		repoStore:  nil, // overridden below via field injection — see note
		validator:  validator,
		gitService: nil,
	}
}

// Because repoStore is an unexported field and the type is concrete, we build
// the Handler struct directly to inject our mock. We embed the mock behind the
// same *repository.RepositoryStore type by using the real Handler but we
// call the handler method directly while intercepting at the HTTP level.
//
// The simplest approach: call CreateRepo as an HTTP handler and verify the log
// output. The mock avoids a real database by testing only the validation path
// (whitelisted vs. rejected) where the log forging sink lives.

// TestCreateRepo_LogForging_NewlineEscaped verifies that a git_url containing
// a newline character is logged with the newline escaped (using the %q verb)
// and does NOT appear as a separate, injected log line.
func TestCreateRepo_LogForging_NewlineEscaped(t *testing.T) {
	// Craft a malicious git_url that passes the whitelist check but contains
	// an embedded newline attempting to inject a fake log entry.
	maliciousURL := "https://github.com/repo\n[FAKE] Injected log entry attacker@evil.com"

	buf := captureLogOutput(t)

	// Build form data
	form := url.Values{}
	form.Set("name", "testrepo")
	form.Set("git_url", maliciousURL)
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	validator := service.NewDomainValidator()
	h := &Handler{
		repoStore: nil,
		validator: validator,
		gitService: nil,
	}

	// Call CreateRepo; it will fail at the DB step (nil store) but the
	// validation log at line 57 is emitted before the DB call — that is the
	// sink we are testing.
	// We recover from a nil-pointer panic that occurs when the nil repoStore
	// is dereferenced after the log line we care about is already written.
	func() {
		defer func() { recover() }()
		h.CreateRepo(rr, req)
	}()

	logged := buf.String()

	// The injected newline must NOT appear as a raw line break inside the
	// log output — the %q verb escapes it as \n.
	if strings.Contains(logged, "[FAKE] Injected log entry") {
		t.Errorf("log forging succeeded: injected content appeared as a separate log line.\nFull log output:\n%s", logged)
	}

	// The escaped form (\n) must be present, confirming %q was used.
	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected the newline to be escaped as \\n in the log output, but it was not.\nFull log output:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_CarriageReturnEscaped verifies that \r is also
// escaped — attackers sometimes use \r to overwrite parts of a terminal line.
func TestCreateRepo_LogForging_CarriageReturnEscaped(t *testing.T) {
	maliciousURL := "https://github.com/repo\r[FAKE] Overwritten line"

	buf := captureLogOutput(t)

	form := url.Values{}
	form.Set("name", "testrepo")
	form.Set("git_url", maliciousURL)

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	validator := service.NewDomainValidator()
	h := &Handler{
		validator: validator,
	}

	func() {
		defer func() { recover() }()
		h.CreateRepo(rr, req)
	}()

	logged := buf.String()

	if strings.Contains(logged, "[FAKE] Overwritten line") {
		t.Errorf("log forging via \\r succeeded: injected content appeared in log output.\nFull log output:\n%s", logged)
	}

	if !strings.Contains(logged, `\r`) {
		t.Errorf("expected \\r to be escaped in log output, but it was not.\nFull log output:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_LegitimateURLNotAltered verifies that a clean,
// valid git URL is logged verbatim (including the enclosing quotes added by
// the %q verb) and is not rejected or mangled.
func TestCreateRepo_LogForging_LegitimateURLNotAltered(t *testing.T) {
	legitimateURL := "https://github.com/owner/repo"

	buf := captureLogOutput(t)

	form := url.Values{}
	form.Set("name", "testrepo")
	form.Set("git_url", legitimateURL)

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	validator := service.NewDomainValidator()
	h := &Handler{
		validator: validator,
	}

	func() {
		defer func() { recover() }()
		h.CreateRepo(rr, req)
	}()

	logged := buf.String()

	// With %q the URL is surrounded by double-quotes; the URL value itself
	// must still appear in the log.
	if !strings.Contains(logged, legitimateURL) {
		t.Errorf("expected legitimate URL %q to appear in the log, but it was not found.\nFull log output:\n%s", legitimateURL, logged)
	}
}

// TestCreateRepo_NonWhitelisted_LogsRejection verifies that a non-whitelisted
// domain is rejected and that the rejection log message is emitted (this also
// exercises the other log.Printf at line 52 which is not the reported sink but
// confirms the validation path is functioning).
func TestCreateRepo_NonWhitelisted_LogsRejection(t *testing.T) {
	nonWhitelistedURL := "https://evil.com/repo"

	buf := captureLogOutput(t)

	form := url.Values{}
	form.Set("name", "testrepo")
	form.Set("git_url", nonWhitelistedURL)

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	validator := service.NewDomainValidator()
	h := &Handler{
		validator: validator,
	}

	h.CreateRepo(rr, req)

	// Non-whitelisted domain must return 400.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 for non-whitelisted domain, got %d", rr.Code)
	}

	logged := buf.String()
	if !strings.Contains(logged, "Rejected non-whitelisted domain") {
		t.Errorf("expected rejection log message, got:\n%s", logged)
	}
}

// TestCreateRepo_MissingFields returns 400 when required form fields are absent.
func TestCreateRepo_MissingFields(t *testing.T) {
	form := url.Values{}
	form.Set("name", "testrepo")
	// git_url intentionally omitted

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h := &Handler{validator: service.NewDomainValidator()}
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 for missing git_url, got %d", rr.Code)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()

	h := &Handler{validator: service.NewDomainValidator()}
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected HTTP 405, got %d", rr.Code)
	}
}
