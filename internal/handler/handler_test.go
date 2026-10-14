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

// newTestHandler creates a Handler wired to an in-memory SQLite database.
func newTestHandler(t *testing.T) (*Handler, *bytes.Buffer) {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite3: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name      TEXT    NOT NULL,
		git_url   TEXT    NOT NULL,
		repo_type TEXT    NOT NULL,
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	gitService := service.NewGitService(t.TempDir())

	h := NewHandler(repoStore, validator, gitService)

	// Redirect the standard logger to a buffer so tests can inspect log output.
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(nil) })

	return h, &logBuf
}

// postForm sends a POST request with form values to handler fn and returns the recorder.
func postForm(t *testing.T, h http.HandlerFunc, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// ── Log-forging prevention tests ──────────────────────────────────────────────

// TestCreateRepo_LogForging_NewlineInName verifies that a repository name
// containing a newline character does NOT appear unescaped in the log output.
// An attacker could inject "\nFAKE LOG ENTRY" to forge audit records.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	h, logBuf := newTestHandler(t)

	maliciousName := "legit\nFAKE] Injected log entry"
	values := url.Values{
		"name":      {maliciousName},
		"git_url":   {"https://github.com/user/repo"},
		"repo_type": {"git"},
	}

	rr := postForm(t, h.CreateRepo, values)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := logBuf.String()

	// The raw newline must NOT appear in the log.
	if strings.Contains(logOutput, "\n[FAKE]") || strings.Contains(logOutput, "\nFAKE]") {
		t.Errorf("log forging succeeded: raw newline found in log output:\n%s", logOutput)
	}

	// The name must still appear in the log, but safely quoted (e.g. \\n).
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("expected escaped newline (\\n) in log output, got:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInName verifies that \r is escaped.
func TestCreateRepo_LogForging_CarriageReturnInName(t *testing.T) {
	h, logBuf := newTestHandler(t)

	maliciousName := "legit\rFAKE] Overwritten log entry"
	values := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/user/repo"},
	}

	rr := postForm(t, h.CreateRepo, values)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := logBuf.String()
	if strings.Contains(logOutput, "\rFAKE]") {
		t.Errorf("log forging via CR succeeded: raw \\r found in log:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, `\r`) {
		t.Errorf("expected escaped \\r in log output, got:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_TabInName verifies that tab characters are escaped.
func TestCreateRepo_LogForging_TabInName(t *testing.T) {
	h, logBuf := newTestHandler(t)

	maliciousName := "name\twith\ttabs"
	values := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/user/repo"},
	}

	rr := postForm(t, h.CreateRepo, values)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := logBuf.String()
	// %q wraps the value in double-quotes; the name with tabs must appear as \t
	if !strings.Contains(logOutput, `\t`) {
		t.Errorf("expected escaped \\t in log output, got:\n%s", logOutput)
	}
}

// ── Normal operation tests ─────────────────────────────────────────────────────

// TestCreateRepo_ValidInput verifies successful creation with a clean name.
func TestCreateRepo_ValidInput(t *testing.T) {
	h, _ := newTestHandler(t)

	values := url.Values{
		"name":      {"my-repo"},
		"git_url":   {"https://github.com/user/my-repo"},
		"repo_type": {"git"},
	}

	rr := postForm(t, h.CreateRepo, values)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
}

// TestCreateRepo_LogContainsQuotedName verifies the log entry uses %q formatting
// for the repo name so that the output is double-quoted.
func TestCreateRepo_LogContainsQuotedName(t *testing.T) {
	h, logBuf := newTestHandler(t)

	values := url.Values{
		"name":    {"hello-world"},
		"git_url": {"https://github.com/user/hello-world"},
	}

	rr := postForm(t, h.CreateRepo, values)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := logBuf.String()
	// %q produces: name="hello-world"
	if !strings.Contains(logOutput, `name="hello-world"`) {
		t.Errorf("expected log to contain name=\"hello-world\", got:\n%s", logOutput)
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields return 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	h, _ := newTestHandler(t)

	tests := []struct {
		label  string
		values url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/user/repo"}}},
		{"missing git_url", url.Values{"name": {"myrepo"}}},
		{"missing both", url.Values{}},
	}

	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			rr := postForm(t, h.CreateRepo, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a non-whitelisted git URL is rejected.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h, _ := newTestHandler(t)

	values := url.Values{
		"name":    {"evil-repo"},
		"git_url": {"https://evil.com/user/repo"},
	}

	rr := postForm(t, h.CreateRepo, values)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that GET requests return 405.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}
