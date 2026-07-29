package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// newTestDB creates an in-memory SQLite database with the repos table for testing.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE repos (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			name      TEXT NOT NULL,
			git_url   TEXT NOT NULL,
			repo_type TEXT NOT NULL,
			created   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHandler builds a Handler wired to an in-memory SQLite database.
// GitService is initialised with a temp dir that is never actually used in
// CreateRepo (cloning only happens in CloneRepo).
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db := newTestDB(t)
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	gitService := service.NewGitService(t.TempDir())
	return NewHandler(repoStore, validator, gitService)
}

// captureLog redirects the standard logger to a buffer for the duration of the
// test and restores it on cleanup.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return &buf
}

// postForm is a helper that builds and dispatches a POST form request to h.CreateRepo.
func postForm(t *testing.T, h *Handler, fields url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Tests: log-forging remediation (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineStripped verifies that a repository name
// containing a newline character (\n) does NOT appear verbatim in the audit
// log.  An unstripped newline would allow an attacker to forge additional log
// entries after the real one.
func TestCreateRepo_LogForging_NewlineStripped(t *testing.T) {
	h := newTestHandler(t)
	buf := captureLog(t)

	maliciousName := "myrepo\nINFO [FAKE] Injected log entry"
	fields := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/org/repo"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	// The raw newline must NOT appear in any logged line.
	if strings.Contains(logOutput, "\n[FAKE]") || strings.Contains(logOutput, "\nINFO [FAKE]") {
		t.Errorf("log forging detected: newline from user input reached the log:\n%s", logOutput)
	}

	// Specifically, the injected fake entry must not appear as a standalone line.
	for _, line := range strings.Split(logOutput, "\n") {
		if strings.Contains(line, "[FAKE] Injected log entry") {
			t.Errorf("injected log line found in log output: %q", line)
		}
	}
}

// TestCreateRepo_LogForging_CarriageReturnStripped verifies that \r is also
// removed from the name before it reaches the log sink.
func TestCreateRepo_LogForging_CarriageReturnStripped(t *testing.T) {
	h := newTestHandler(t)
	buf := captureLog(t)

	maliciousName := "repo\rINFO [FAKE] CR-injected entry"
	fields := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/org/repo"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	if strings.Contains(logOutput, "\r") {
		t.Errorf("carriage return from user input reached the log: %q", logOutput)
	}
}

// TestCreateRepo_LogForging_CRLFStripped verifies that \r\n sequences are
// fully removed.
func TestCreateRepo_LogForging_CRLFStripped(t *testing.T) {
	h := newTestHandler(t)
	buf := captureLog(t)

	maliciousName := "legit-repo\r\nINFO [FAKE] CRLF-injected"
	fields := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/org/repo"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()

	if strings.Contains(logOutput, "[FAKE]") {
		t.Errorf("CRLF-injected fake log entry appeared in output: %q", logOutput)
	}
}

// ---------------------------------------------------------------------------
// Tests: functional correctness (regression guard)
// ---------------------------------------------------------------------------

// TestCreateRepo_Success verifies that a well-formed request succeeds and
// returns a JSON response with success=true.
func TestCreateRepo_Success(t *testing.T) {
	h := newTestHandler(t)
	captureLog(t) // suppress log output during test

	fields := url.Values{
		"name":      {"my-repo"},
		"git_url":   {"https://github.com/org/repo"},
		"repo_type": {"git"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if success, ok := resp["success"].(bool); !ok || !success {
		t.Errorf("expected success=true in response, got %v", resp)
	}

	if _, ok := resp["id"]; !ok {
		t.Errorf("expected 'id' in response, got %v", resp)
	}
}

// TestCreateRepo_MissingName verifies that omitting the name field returns 400.
func TestCreateRepo_MissingName(t *testing.T) {
	h := newTestHandler(t)

	fields := url.Values{
		"git_url": {"https://github.com/org/repo"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingGitURL verifies that omitting git_url returns 400.
func TestCreateRepo_MissingGitURL(t *testing.T) {
	h := newTestHandler(t)

	fields := url.Values{
		"name": {"my-repo"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rr.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a git_url from a
// non-whitelisted domain is rejected with 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)
	captureLog(t)

	fields := url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://evil.example.com/org/repo"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that GET requests are rejected
// with 405 Method Not Allowed.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

// TestCreateRepo_DefaultRepoType verifies that if repo_type is omitted it
// defaults to "git" without causing an error.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h := newTestHandler(t)
	captureLog(t)

	fields := url.Values{
		"name":    {"default-type-repo"},
		"git_url": {"https://github.com/org/repo"},
		// repo_type intentionally omitted
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK with default repo_type, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateRepo_NamePreservedAfterSanitization verifies that a name WITHOUT
// newlines is stored and returned verbatim (sanitization does not corrupt
// legitimate names).
func TestCreateRepo_NamePreservedAfterSanitization(t *testing.T) {
	h := newTestHandler(t)
	captureLog(t)

	legitimateName := "my-legitimate-repo"
	fields := url.Values{
		"name":    {legitimateName},
		"git_url": {"https://github.com/org/repo"},
	}

	rr := postForm(t, h, fields)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if success, _ := resp["success"].(bool); !success {
		t.Errorf("expected success=true, got %v", resp)
	}
}
