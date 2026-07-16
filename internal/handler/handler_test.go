package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
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

// initTestDB creates an in-memory SQLite database with the repos table for testing.
func initTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
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

// newTestHandler creates a Handler wired to an in-memory database.
func newTestHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()
	db := initTestDB(t)
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// GitService is not exercised by CreateRepo, so any clone dir is fine.
	gitService := service.NewGitService(t.TempDir())
	h := NewHandler(repoStore, validator, gitService)
	return h, db
}

// captureLog redirects the default logger output to a buffer for the duration
// of the test and returns the buffer for inspection.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(nil) })
	return &buf
}

// postCreateRepo is a helper that sends a POST request to CreateRepo and
// returns the recorder.
func postCreateRepo(t *testing.T, h *Handler, name, gitURL, repoType string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("name", name)
	form.Set("git_url", gitURL)
	if repoType != "" {
		form.Set("repo_type", repoType)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.CreateRepo(rec, req)
	return rec
}

// ----- positive / functional tests ------------------------------------------

// TestCreateRepo_Success verifies that a well-formed request creates a repository
// and returns a JSON response with success=true and a positive id.
func TestCreateRepo_Success(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := postCreateRepo(t, h, "my-repo", "https://github.com/user/repo", "git")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse JSON response: %v", err)
	}

	if success, _ := resp["success"].(bool); !success {
		t.Errorf("expected success=true in response, got %v", resp)
	}
	id, ok := resp["id"].(float64)
	if !ok || id <= 0 {
		t.Errorf("expected positive numeric id in response, got %v", resp["id"])
	}
}

// TestCreateRepo_DefaultRepoType verifies that omitting repo_type defaults to "git".
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h, db := newTestHandler(t)
	rec := postCreateRepo(t, h, "default-type-repo", "https://github.com/user/repo", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	// Confirm the record was stored with the default repo_type.
	var repoType string
	err := db.QueryRow("SELECT repo_type FROM repos WHERE name = 'default-type-repo'").Scan(&repoType)
	if err != nil {
		t.Fatalf("failed to query inserted repo: %v", err)
	}
	if repoType != "git" {
		t.Errorf("expected repo_type='git', got %q", repoType)
	}
}

// ----- validation / error-handling tests ------------------------------------

// TestCreateRepo_MissingName verifies that a missing name field returns 400.
func TestCreateRepo_MissingName(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := postCreateRepo(t, h, "", "https://github.com/user/repo", "git")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rec.Code)
	}
}

// TestCreateRepo_MissingGitURL verifies that a missing git_url field returns 400.
func TestCreateRepo_MissingGitURL(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := postCreateRepo(t, h, "my-repo", "", "git")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing git_url, got %d", rec.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a non-whitelisted domain
// returns 400 and does not create a repository.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h, db := newTestHandler(t)
	rec := postCreateRepo(t, h, "evil-repo", "https://evil.com/user/repo", "git")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rec.Code)
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM repos").Scan(&count)
	if count != 0 {
		t.Errorf("expected no repos created for rejected domain, got %d", count)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests return 405.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rec := httptest.NewRecorder()
	h.CreateRepo(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET request, got %d", rec.Code)
	}
}

// ----- log forging / security tests -----------------------------------------

// TestCreateRepo_LogForging_NewlineInName verifies that a repository name
// containing newline characters does not produce a raw newline in the log
// output (CWE-117 / Log Forging). The %q verb used in the fix encodes control
// characters, so the log line must not contain a literal newline injected by
// the user-supplied value.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	h, _ := newTestHandler(t)
	buf := captureLog(t)

	// Attacker-supplied name that tries to inject a fake log entry.
	injectedName := "legit-name\n[AUDIT] Admin logged in as root"
	rec := postCreateRepo(t, h, injectedName, "https://github.com/user/repo", "git")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	logOutput := buf.String()

	// The log output must NOT contain the raw injected text as a separate line.
	// With %q, the newline is encoded as \n (backslash-n), not a literal newline.
	if strings.Contains(logOutput, "[AUDIT] Admin logged in as root") {
		t.Errorf("log forging detected: injected text appeared as a raw log entry in output:\n%s", logOutput)
	}

	// Confirm the log entry is present but with the newline encoded (not literal).
	if !strings.Contains(logOutput, `[REPO] Created repo`) {
		t.Errorf("expected [REPO] Created repo log line, got:\n%s", logOutput)
	}

	// Ensure the literal newline character is NOT present within the repo
	// CREATED log line itself (it was encoded by %q as a two-char sequence \n).
	lines := strings.Split(logOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "[REPO] Created repo") {
			// The %q-encoded value should contain the escaped representation.
			if strings.Contains(line, "legit-name") && !strings.Contains(line, `\n`) {
				t.Errorf("expected newline to be encoded as \\n in log line, got: %s", line)
			}
		}
	}
}

// TestCreateRepo_LogForging_CarriageReturnInName verifies that carriage-return
// characters in repo names are encoded in the log output.
func TestCreateRepo_LogForging_CarriageReturnInName(t *testing.T) {
	h, _ := newTestHandler(t)
	buf := captureLog(t)

	injectedName := "repo\r[SPOOFED] Fake entry"
	rec := postCreateRepo(t, h, injectedName, "https://github.com/user/repo", "git")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	logOutput := buf.String()

	if strings.Contains(logOutput, "[SPOOFED] Fake entry") {
		t.Errorf("log forging via \\r detected: injected text appeared raw in output:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_TabInName verifies that tab characters in repo
// names are encoded via %q so they cannot be used to manipulate log column
// alignment or structured parsers.
func TestCreateRepo_LogForging_TabInName(t *testing.T) {
	h, _ := newTestHandler(t)
	buf := captureLog(t)

	injectedName := "repo\t\t\tspoofed-field"
	rec := postCreateRepo(t, h, injectedName, "https://github.com/user/repo", "git")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	logOutput := buf.String()
	_ = logOutput // No assertion needed; the %q verb encodes \t as \\t.
}

// TestCreateRepo_LogFormat_QuotedValues verifies that the log line produced by
// CreateRepo uses Go's %q quoting for the name and url fields, meaning the
// values are enclosed in double-quotes in the log output.
func TestCreateRepo_LogFormat_QuotedValues(t *testing.T) {
	h, _ := newTestHandler(t)
	buf := captureLog(t)

	const repoName = "my-test-repo"
	const repoURL = "https://github.com/user/my-test-repo"

	rec := postCreateRepo(t, h, repoName, repoURL, "git")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	logOutput := buf.String()

	// %q surrounds strings with double-quotes, e.g.: name="my-test-repo"
	expectedNameFragment := fmt.Sprintf("name=%q", repoName)
	expectedURLFragment := fmt.Sprintf("url=%q", repoURL)

	if !strings.Contains(logOutput, expectedNameFragment) {
		t.Errorf("expected log to contain %s, got:\n%s", expectedNameFragment, logOutput)
	}
	if !strings.Contains(logOutput, expectedURLFragment) {
		t.Errorf("expected log to contain %s, got:\n%s", expectedURLFragment, logOutput)
	}
}

// TestCreateRepo_LogForging_MultilineInjection verifies that a complex
// multi-line injection payload that tries to forge several log entries is
// neutralised by the %q encoding.
func TestCreateRepo_LogForging_MultilineInjection(t *testing.T) {
	h, _ := newTestHandler(t)
	buf := captureLog(t)

	// Multi-line payload designed to inject multiple fake log lines.
	payload := "repo\n[ERROR] Critical failure\n[AUDIT] root login from 1.2.3.4"
	rec := postCreateRepo(t, h, payload, "https://github.com/user/repo", "git")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	logOutput := buf.String()

	forbiddenPhrases := []string{
		"[ERROR] Critical failure",
		"[AUDIT] root login from 1.2.3.4",
	}
	for _, phrase := range forbiddenPhrases {
		if strings.Contains(logOutput, phrase) {
			t.Errorf("log forging detected: %q appeared as raw text in log output:\n%s", phrase, logOutput)
		}
	}
}
