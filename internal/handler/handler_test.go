package handler_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/checkmarx/correlation-demo/internal/handler"
	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// setupTestDB creates an in-memory SQLite database with the required schema.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS repos (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			name     TEXT NOT NULL,
			git_url  TEXT NOT NULL,
			repo_type TEXT NOT NULL DEFAULT 'git',
			created  DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to create repos table: %v", err)
	}
	return db
}

// newTestHandler wires up a Handler backed by an in-memory SQLite store.
// GitService is intentionally not exercised by these handler-level tests
// (CloneRepo is a network operation); a nil git service is fine for CreateRepo
// and ListRepos tests.
func newTestHandler(t *testing.T) (*handler.Handler, *sql.DB) {
	t.Helper()
	db := setupTestDB(t)
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// GitService is not used by the tested handlers; pass a dummy instance.
	gitSvc := service.NewGitService(t.TempDir())
	h := handler.NewHandler(repoStore, validator, gitSvc)
	return h, db
}

// captureLogOutput redirects the standard logger to a buffer and returns it,
// along with a cleanup function that restores the original output.
func captureLogOutput(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	return &buf, func() {
		log.SetOutput(os.Stderr)
	}
}

// ---------------------------------------------------------------------------
// CreateRepo – log forging remediation tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInGitURL verifies that a git_url containing
// embedded newlines does NOT produce forged log lines.
func TestCreateRepo_LogForging_NewlineInGitURL(t *testing.T) {
	h, _ := newTestHandler(t)
	logBuf, restore := captureLogOutput(t)
	defer restore()

	// Attacker payload: a valid-looking whitelisted URL followed by a fake log
	// entry injected via a newline character.
	maliciousURL := "https://github.com/legit/repo\n[ADMIN] User 'root' logged in successfully"

	form := url.Values{}
	form.Set("name", "test-repo")
	form.Set("git_url", maliciousURL)
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	logOutput := logBuf.String()

	// The forged log entry must NOT appear in the log output.
	if strings.Contains(logOutput, "[ADMIN] User 'root' logged in successfully") {
		t.Errorf("log forging vulnerability: injected fake log entry found in log output:\n%s", logOutput)
	}

	// The newline character itself must not appear in the logged URL segment.
	if strings.Contains(logOutput, "\n[ADMIN]") {
		t.Errorf("log forging vulnerability: raw newline from user input found in log output:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInGitURL verifies that a git_url
// containing an embedded carriage return (\r) does not forge log entries.
func TestCreateRepo_LogForging_CarriageReturnInGitURL(t *testing.T) {
	h, _ := newTestHandler(t)
	logBuf, restore := captureLogOutput(t)
	defer restore()

	maliciousURL := "https://github.com/legit/repo\r\n[SECURITY] Password reset for admin"

	form := url.Values{}
	form.Set("name", "cr-test")
	form.Set("git_url", maliciousURL)

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	logOutput := logBuf.String()

	if strings.Contains(logOutput, "[SECURITY] Password reset for admin") {
		t.Errorf("log forging via CR+LF: injected log entry found in output:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_NewlineInName verifies that the name field is also
// sanitized before being written to the log.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	h, _ := newTestHandler(t)
	logBuf, restore := captureLogOutput(t)
	defer restore()

	maliciousName := "good-repo\n[AUDIT] Privilege escalation performed"

	form := url.Values{}
	form.Set("name", maliciousName)
	form.Set("git_url", "https://github.com/legit/repo")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	logOutput := logBuf.String()

	if strings.Contains(logOutput, "[AUDIT] Privilege escalation performed") {
		t.Errorf("log forging via name field: injected entry found in log output:\n%s", logOutput)
	}
}

// ---------------------------------------------------------------------------
// CreateRepo – functional correctness tests
// ---------------------------------------------------------------------------

// TestCreateRepo_Success verifies that a well-formed request creates a repo and
// returns the expected JSON response.
func TestCreateRepo_Success(t *testing.T) {
	h, _ := newTestHandler(t)

	form := url.Values{}
	form.Set("name", "my-repo")
	form.Set("git_url", "https://github.com/example/my-repo")
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}

	if success, _ := resp["success"].(bool); !success {
		t.Errorf("expected success=true, got: %v", resp["success"])
	}
	if _, ok := resp["id"]; !ok {
		t.Errorf("expected 'id' field in response, got: %v", resp)
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields return 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	h, _ := newTestHandler(t)

	tests := []struct {
		name string
		form url.Values
	}{
		{
			name: "missing name",
			form: url.Values{"git_url": {"https://github.com/example/repo"}},
		},
		{
			name: "missing git_url",
			form: url.Values{"name": {"my-repo"}},
		},
		{
			name: "both missing",
			form: url.Values{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			h.CreateRepo(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that non-whitelisted git URLs
// are rejected with 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h, _ := newTestHandler(t)

	form := url.Values{}
	form.Set("name", "evil-repo")
	form.Set("git_url", "https://evil.example.com/attacker/repo")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_DefaultRepoType verifies that an omitted repo_type defaults to
// "git" (observable indirectly through the successful 200 response).
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h, _ := newTestHandler(t)

	form := url.Values{}
	form.Set("name", "default-type-repo")
	form.Set("git_url", "https://github.com/example/repo")
	// repo_type intentionally omitted

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK when repo_type omitted, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateRepo_ValidGitLabURL verifies that gitlab.com URLs are accepted.
func TestCreateRepo_ValidGitLabURL(t *testing.T) {
	h, _ := newTestHandler(t)

	form := url.Values{}
	form.Set("name", "gitlab-repo")
	form.Set("git_url", "https://gitlab.com/example/project")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 OK for gitlab.com URL, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// ListRepos tests
// ---------------------------------------------------------------------------

// TestListRepos_EmptyDatabase verifies that listing repos on an empty DB
// returns an empty JSON array and 200.
func TestListRepos_EmptyDatabase(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/repos", nil)
	rr := httptest.NewRecorder()

	h.ListRepos(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var repos []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&repos); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if len(repos) != 0 {
		t.Errorf("expected empty list, got %d items", len(repos))
	}
}

// TestListRepos_AfterCreate verifies that a created repo appears in the list.
func TestListRepos_AfterCreate(t *testing.T) {
	h, _ := newTestHandler(t)

	// Create a repo first.
	form := url.Values{}
	form.Set("name", "list-test-repo")
	form.Set("git_url", "https://github.com/example/list-test")

	createReq := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	createReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateRepo(httptest.NewRecorder(), createReq)

	// Now list.
	listReq := httptest.NewRequest(http.MethodGet, "/repos", nil)
	rr := httptest.NewRecorder()
	h.ListRepos(rr, listReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var repos []map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&repos); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if len(repos) != 1 {
		t.Errorf("expected 1 repo, got %d", len(repos))
	}
	if repos[0]["name"] != "list-test-repo" {
		t.Errorf("expected name 'list-test-repo', got %q", repos[0]["name"])
	}
}

// TestListRepos_MethodNotAllowed verifies that POST to /repos is rejected.
func TestListRepos_MethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/repos", nil)
	rr := httptest.NewRecorder()

	h.ListRepos(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}
