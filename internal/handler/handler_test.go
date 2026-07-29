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

// initTestDB creates an in-memory SQLite database for testing.
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
		t.Fatalf("failed to create test table: %v", err)
	}
	return db
}

// newTestHandler builds a Handler wired to an in-memory database.
// GitService is left nil because CreateRepo does not use it.
func newTestHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()
	db := initTestDB(t)
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	h := NewHandler(repoStore, validator, nil)
	return h, db
}

// postCreateRepo is a helper that fires a POST /create request and returns
// the recorded response.
func postCreateRepo(t *testing.T, h *Handler, formValues url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(formValues.Encode())
	req := httptest.NewRequest(http.MethodPost, "/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Log-forging remediation tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_GitURL_NewlinesStripped verifies that CR/LF characters injected
// into the git_url form field are removed before the value is used in any log
// statement or persisted, preventing log forging.
func TestCreateRepo_GitURL_NewlinesStripped(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	// Capture log output so we can assert no injected lines appear.
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(nil) // restore default after test

	attackPayload := "https://github.com/owner/repo\nFAKE LOG ENTRY injected by attacker"

	form := url.Values{}
	form.Set("name", "test-repo")
	form.Set("git_url", attackPayload)
	form.Set("repo_type", "git")

	rr := postCreateRepo(t, h, form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := logBuf.String()

	// The injected text must NOT appear as a separate line in the log.
	if strings.Contains(logOutput, "FAKE LOG ENTRY injected by attacker") {
		t.Errorf("log forging not prevented: injected text found in log output:\n%s", logOutput)
	}

	// The newline itself must not be present inside any logged URL value.
	if strings.Contains(logOutput, "\n[") {
		// A genuine log line starts with the timestamp prefix produced by log.Printf.
		// If an injected \n followed by what looks like a log prefix appears, that is
		// evidence of a forged entry.
		t.Errorf("possible forged log entry detected in log output:\n%s", logOutput)
	}
}

// TestCreateRepo_GitURL_CRLFStripped verifies that Windows-style CRLF sequences
// are also stripped, preventing forged entries on systems that split on \r\n.
func TestCreateRepo_GitURL_CRLFStripped(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(nil)

	attackPayload := "https://github.com/owner/repo\r\nFAKE CRLF ENTRY"

	form := url.Values{}
	form.Set("name", "crlf-repo")
	form.Set("git_url", attackPayload)

	rr := postCreateRepo(t, h, form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := logBuf.String()

	if strings.Contains(logOutput, "FAKE CRLF ENTRY") {
		t.Errorf("CRLF log forging not prevented: injected text found in log output:\n%s", logOutput)
	}
	if strings.Contains(logOutput, "\r\n") {
		t.Errorf("CRLF sequence not stripped from log output")
	}
}

// TestCreateRepo_GitURL_MultipleNewlinesStripped verifies that multiple embedded
// newlines are all removed, not just the first one.
func TestCreateRepo_GitURL_MultipleNewlinesStripped(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(nil)

	// Three injected lines after a valid GitHub URL.
	attackPayload := "https://github.com/owner/repo\nLINE1\nLINE2\nLINE3"

	form := url.Values{}
	form.Set("name", "multi-repo")
	form.Set("git_url", attackPayload)

	rr := postCreateRepo(t, h, form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := logBuf.String()

	for _, injected := range []string{"LINE1", "LINE2", "LINE3"} {
		if strings.Contains(logOutput, injected) {
			t.Errorf("log forging not fully prevented: %q still appears in log output", injected)
		}
	}
}

// ---------------------------------------------------------------------------
// Normal operation tests (regression / positive path)
// ---------------------------------------------------------------------------

// TestCreateRepo_ValidURL_Succeeds confirms that a clean whitelisted URL still
// creates a repository and returns a 200 response after the sanitization fix.
func TestCreateRepo_ValidURL_Succeeds(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "my-repo")
	form.Set("git_url", "https://github.com/owner/my-repo")
	form.Set("repo_type", "git")

	rr := postCreateRepo(t, h, form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if success, ok := resp["success"].(bool); !ok || !success {
		t.Errorf("expected success=true in response, got %v", resp)
	}
	if _, ok := resp["id"]; !ok {
		t.Errorf("expected 'id' field in response, got %v", resp)
	}
}

// TestCreateRepo_GitLabURL_Succeeds verifies gitlab.com URLs are also accepted.
func TestCreateRepo_GitLabURL_Succeeds(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "gitlab-repo")
	form.Set("git_url", "https://gitlab.com/group/project")

	rr := postCreateRepo(t, h, form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateRepo_DefaultRepoType_UsedWhenEmpty verifies that an empty repo_type
// defaults to "git".
func TestCreateRepo_DefaultRepoType_UsedWhenEmpty(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "default-type-repo")
	form.Set("git_url", "https://github.com/owner/repo")
	// intentionally omit repo_type

	rr := postCreateRepo(t, h, form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateRepo_NonWhitelistedURL_Rejected verifies that non-whitelisted domains
// are rejected with 400 Bad Request.
func TestCreateRepo_NonWhitelistedURL_Rejected(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "evil-repo")
	form.Set("git_url", "https://evil.example.com/owner/repo")

	rr := postCreateRepo(t, h, form)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields_ReturnsBadRequest verifies that missing name or
// git_url returns a 400 status.
func TestCreateRepo_MissingFields_ReturnsBadRequest(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
	}{
		{
			name: "missing name",
			form: url.Values{"git_url": {"https://github.com/owner/repo"}},
		},
		{
			name: "missing git_url",
			form: url.Values{"name": {"some-repo"}},
		},
		{
			name: "both missing",
			form: url.Values{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, db := newTestHandler(t)
			defer db.Close()

			rr := postCreateRepo(t, h, tc.form)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_WrongMethod_MethodNotAllowed verifies that GET requests to
// CreateRepo are rejected with 405.
func TestCreateRepo_WrongMethod_MethodNotAllowed(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

// TestCreateRepo_GitURL_OnlyNewlineAfterHost_StillRejectedOrSanitized verifies
// that a payload where the whitelisted host prefix is followed by a newline and
// then a different domain does not bypass the domain check via forged log entries.
// The sanitized URL must either be accepted (because the remaining value still
// contains the whitelisted domain) or rejected — but must never log an injected line.
func TestCreateRepo_GitURL_InjectedNewlineNotLogged(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	defer log.SetOutput(nil)

	// Attempt to inject a fake "Domain validated successfully" log line.
	attackPayload := "https://github.com/owner/repo\n[VALIDATION] Domain validated successfully: https://evil.com"

	form := url.Values{}
	form.Set("name", "inject-test")
	form.Set("git_url", attackPayload)

	// We don't care whether the request succeeds or not; we care that the log
	// does not contain the injected text.
	postCreateRepo(t, h, form)

	logOutput := logBuf.String()
	if strings.Contains(logOutput, "https://evil.com") {
		t.Errorf("injected evil.com URL appeared in log output — log forging not prevented:\n%s", logOutput)
	}
	if strings.Contains(logOutput, "[VALIDATION] Domain validated successfully: https://evil.com") {
		t.Errorf("forged validation log entry appeared in output:\n%s", logOutput)
	}
}
