package handler

import (
	"bytes"
	"database/sql"
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

// setupTestDB creates an in-memory SQLite database with the repos table.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory database: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name      TEXT    NOT NULL,
		git_url   TEXT    NOT NULL,
		repo_type TEXT    NOT NULL DEFAULT 'git',
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("failed to create repos table: %v", err)
	}

	return db
}

// newTestHandler builds a Handler wired to an in-memory store.
// gitService is nil because CloneRepo is not tested here.
func newTestHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()
	db := setupTestDB(t)
	store := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	h := NewHandler(store, validator, nil)
	return h, db
}

// captureLog redirects the standard logger output and returns the captured bytes.
// The returned function restores the original output.
func captureLog() (*bytes.Buffer, func()) {
	buf := &bytes.Buffer{}
	original := log.Writer()
	log.SetOutput(buf)
	return buf, func() { log.SetOutput(original) }
}

// ─── CreateRepo – happy path ───────────────────────────────────────────────

// TestCreateRepo_Success verifies a well-formed POST creates a repo and returns
// a JSON response with success=true.
func TestCreateRepo_Success(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "my-repo")
	form.Set("git_url", "https://github.com/org/my-repo")
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Errorf("expected success=true in body, got: %s", rr.Body.String())
	}
}

// TestCreateRepo_DefaultRepoType verifies that an omitted repo_type defaults to
// "git" without error.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "default-type-repo")
	form.Set("git_url", "https://gitlab.com/org/repo")
	// repo_type intentionally omitted

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ─── CreateRepo – method guard ─────────────────────────────────────────────

func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ─── CreateRepo – missing fields ───────────────────────────────────────────

func TestCreateRepo_MissingFields(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	// neither name nor git_url

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ─── CreateRepo – domain whitelist ─────────────────────────────────────────

func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "evil-repo")
	form.Set("git_url", "https://evil.example.com/org/repo")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// ─── Log Forging prevention (CWE-117) ──────────────────────────────────────

// TestCreateRepo_LogForging_NewlineInName verifies that a newline injected via
// the 'name' field is escaped (quoted) in the audit log rather than emitted as
// a raw newline that would forge an extra log line.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	// Payload that would forge a second log entry if concatenated raw.
	maliciousName := "legit\nINFO Fake log line injected by attacker"

	form := url.Values{}
	form.Set("name", maliciousName)
	form.Set("git_url", "https://github.com/org/repo")
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	logBuf, restore := captureLog()
	defer restore()

	h.CreateRepo(rr, req)

	logged := logBuf.String()

	// The raw newline must NOT appear inside the REPO audit log line.
	// With %q formatting the newline is encoded as \n (two characters).
	if strings.Contains(logged, "Fake log line injected by attacker") {
		t.Errorf("log forging not prevented: forged line appeared in log output:\n%s", logged)
	}

	// Verify the value was still recorded – just safely quoted.
	// %q turns \n into the two-character sequence \n inside double quotes.
	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected escaped newline (\\n) in log output, got:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_NewlineInURL verifies that a newline injected via
// the 'git_url' field is escaped in the audit log.
func TestCreateRepo_LogForging_NewlineInURL(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	// The injected URL passes the whitelist check (contains github.com) but
	// carries a log-forging payload after the newline.
	maliciousURL := "https://github.com/org/repo\nCRIT Fake critical entry"

	form := url.Values{}
	form.Set("name", "normal-name")
	form.Set("git_url", maliciousURL)
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	logBuf, restore := captureLog()
	defer restore()

	h.CreateRepo(rr, req)

	logged := logBuf.String()

	if strings.Contains(logged, "Fake critical entry") {
		t.Errorf("log forging not prevented: forged URL line appeared in log:\n%s", logged)
	}

	// The escaped form (\n) must be present instead.
	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected escaped newline (\\n) in log output, got:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInName verifies that a carriage
// return (\r) — another common log injection character — is also escaped.
func TestCreateRepo_LogForging_CarriageReturnInName(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	maliciousName := "legit\rFORGED"

	form := url.Values{}
	form.Set("name", maliciousName)
	form.Set("git_url", "https://github.com/org/repo")
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	logBuf, restore := captureLog()
	defer restore()

	h.CreateRepo(rr, req)

	logged := logBuf.String()

	// With %q, \r is encoded as \r (two chars) — the raw byte must not appear
	// as a literal carriage return in the REPO audit line.
	repoLogLine := ""
	for _, line := range strings.Split(logged, "\n") {
		if strings.Contains(line, "[REPO]") {
			repoLogLine = line
			break
		}
	}
	if strings.ContainsRune(repoLogLine, '\r') {
		t.Errorf("raw carriage return found in [REPO] log line — log forging not prevented:\n%q", repoLogLine)
	}
}

// TestCreateRepo_LogForging_QuotedFormatInLog verifies that the audit log uses
// the %q (quoted) format verb so that string user-data is surrounded by double
// quotes in the log output, making injection attempts visually distinct and
// non-parseable as additional log fields.
func TestCreateRepo_LogForging_QuotedFormatInLog(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{}
	form.Set("name", "myrepo")
	form.Set("git_url", "https://github.com/org/myrepo")
	form.Set("repo_type", "git")

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	logBuf, restore := captureLog()
	defer restore()

	h.CreateRepo(rr, req)

	logged := logBuf.String()

	// %q wraps the value in double quotes: name="myrepo"
	if !strings.Contains(logged, `name="myrepo"`) {
		t.Errorf("expected quoted name in log (name=\"myrepo\"), got:\n%s", logged)
	}
	if !strings.Contains(logged, `url="https://github.com/org/myrepo"`) {
		t.Errorf("expected quoted url in log, got:\n%s", logged)
	}
}
