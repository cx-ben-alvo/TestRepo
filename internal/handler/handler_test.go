package handler

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// initTestDB creates an in-memory SQLite database with the required schema,
// matching the setup performed by internal/database/database.go.
func initTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE repos (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			git_url TEXT NOT NULL,
			repo_type TEXT NOT NULL,
			created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to create repos table: %v", err)
	}
	return db
}

// newTestHandler wires up a Handler backed by an in-memory SQLite database.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db := initTestDB(t)
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// GitService is not exercised by CreateRepo, so any cloneDir is fine.
	gitService := service.NewGitService(t.TempDir())
	return NewHandler(repoStore, validator, gitService)
}

// captureLog redirects the default logger output to a buffer for the duration
// of the test and returns a pointer to that buffer.  The caller must call the
// returned cleanup function to restore the original logger.
func captureLog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	return &buf, func() { log.SetOutput(old) }
}

// postForm is a helper that sends a POST form request to the given handler.
func postForm(h *Handler, params url.Values) *httptest.ResponseRecorder {
	body := strings.NewReader(params.Encode())
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Tests for CreateRepo – log-forging fix (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInName verifies that a repo name containing
// embedded newline characters does NOT appear verbatim in the log output.
// An attacker could otherwise inject fake log entries, e.g.:
//
//	name = "legit\n[REPO] Fake injected log line"
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	h := newTestHandler(t)
	buf, cleanup := captureLog(t)
	defer cleanup()

	maliciousName := "legit\n[INJECTED] Fake log entry from attacker"
	params := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/example/repo"},
	}

	rr := postForm(h, params)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	// The injected fake log line must NOT appear as a standalone log entry.
	if strings.Contains(logOutput, "[INJECTED]") {
		t.Errorf("log forging not prevented: injected marker found in log output:\n%s", logOutput)
	}

	// The newline character itself must not be present in the logged name.
	if strings.Contains(logOutput, "\n[INJECTED]") {
		t.Errorf("log forging not prevented: embedded newline allowed injection into log:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInName verifies that carriage-return
// characters (which can be used for log entry injection on some platforms) are
// also stripped from the logged name.
func TestCreateRepo_LogForging_CarriageReturnInName(t *testing.T) {
	h := newTestHandler(t)
	buf, cleanup := captureLog(t)
	defer cleanup()

	maliciousName := "legit\r[INJECTED-CR] Fake log entry via CR"
	params := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/example/repo"},
	}

	rr := postForm(h, params)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	if strings.Contains(logOutput, "[INJECTED-CR]") {
		t.Errorf("log forging not prevented: CR-based injected marker found in log output:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_NewlineInURL verifies that embedded newlines in
// the git_url value are also sanitized before logging.
func TestCreateRepo_LogForging_NewlineInURL(t *testing.T) {
	h := newTestHandler(t)
	buf, cleanup := captureLog(t)
	defer cleanup()

	// The URL must still pass the domain whitelist; embed the newline after
	// the allowed domain portion.
	maliciousURL := "https://github.com/example/repo\n[INJECTED-URL] Fake entry"
	params := url.Values{
		"name":    {"myrepo"},
		"git_url": {maliciousURL},
	}

	rr := postForm(h, params)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	if strings.Contains(logOutput, "[INJECTED-URL]") {
		t.Errorf("log forging not prevented: URL-injected marker found in log output:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_MultipleNewlines verifies that multiple embedded
// newline characters in the name are all stripped.
func TestCreateRepo_LogForging_MultipleNewlines(t *testing.T) {
	h := newTestHandler(t)
	buf, cleanup := captureLog(t)
	defer cleanup()

	maliciousName := "a\nb\nc\n[MULTI] Injected"
	params := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/example/repo"},
	}

	rr := postForm(h, params)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	if strings.Contains(logOutput, "[MULTI]") {
		t.Errorf("log forging not prevented: multi-newline injection succeeded:\n%s", logOutput)
	}
}

// TestCreateRepo_LegitimateInput verifies that a normal, well-formed request
// still works correctly after the security fix is applied.
func TestCreateRepo_LegitimateInput(t *testing.T) {
	h := newTestHandler(t)

	params := url.Values{
		"name":      {"my-awesome-repo"},
		"git_url":   {"https://github.com/example/awesome"},
		"repo_type": {"git"},
	}

	rr := postForm(h, params)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["success"] != true {
		t.Errorf("expected success=true in response, got: %v", resp)
	}
	if _, ok := resp["id"]; !ok {
		t.Error("expected 'id' field in response")
	}
}

// TestCreateRepo_MissingName verifies that a missing name field returns 400.
func TestCreateRepo_MissingName(t *testing.T) {
	h := newTestHandler(t)

	params := url.Values{
		"git_url": {"https://github.com/example/repo"},
	}

	rr := postForm(h, params)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingURL verifies that a missing git_url field returns 400.
func TestCreateRepo_MissingURL(t *testing.T) {
	h := newTestHandler(t)

	params := url.Values{
		"name": {"my-repo"},
	}

	rr := postForm(h, params)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a git_url from a
// non-whitelisted domain is rejected with 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)

	params := url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://evil.com/attacker/repo"},
	}

	rr := postForm(h, params)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that GET requests to CreateRepo are
// rejected with 405.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

// TestCreateRepo_LogContainsRepoID verifies that the log entry for a
// successful creation includes the assigned repository ID, confirming
// that the sanitized log statement still emits useful audit information.
func TestCreateRepo_LogContainsRepoID(t *testing.T) {
	h := newTestHandler(t)
	buf, cleanup := captureLog(t)
	defer cleanup()

	params := url.Values{
		"name":    {"audit-test-repo"},
		"git_url": {"https://github.com/example/audit"},
	}

	rr := postForm(h, params)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	// The REPO audit line must still be present and contain "ID=".
	if !strings.Contains(logOutput, "[REPO]") {
		t.Errorf("expected [REPO] audit line in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "ID=") {
		t.Errorf("expected ID= field in [REPO] log line, got:\n%s", logOutput)
	}
}
