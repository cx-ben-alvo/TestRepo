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

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
	_ "github.com/mattn/go-sqlite3"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// openInMemoryDB opens an SQLite in-memory database and creates the repos
// table used by repository.RepositoryStore.
func openInMemoryDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("openInMemoryDB: sql.Open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name      TEXT NOT NULL,
		git_url   TEXT NOT NULL,
		repo_type TEXT NOT NULL DEFAULT 'git',
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("openInMemoryDB: CREATE TABLE: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHandler constructs a Handler backed by a real in-memory SQLite
// database so tests can exercise both the rejection path (no DB hit) and the
// success path (DB insert).
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db := openInMemoryDB(t)
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	return NewHandler(repoStore, validator, nil)
}

// postForm builds a POST request with the supplied form fields.
func postForm(fields map[string]string) *http.Request {
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/repo/create",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// captureLog redirects the standard logger's output to a buffer, calls fn,
// and returns whatever was written to that buffer.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// ---------------------------------------------------------------------------
// CWE-117 Log-Forging regression tests
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInjection is the core regression test for
// CWE-117.  An attacker who supplies a git_url containing a raw newline could
// inject a fake log entry that appears as a separate, legitimate-looking line
// in log files.  After the fix (%q instead of %s) the newline must be escaped
// to the two-character sequence \n inside double-quotes — it must NEVER appear
// as a real newline in the log output.
func TestCreateRepo_LogForging_NewlineInjection(t *testing.T) {
	h := newTestHandler(t)

	// The raw newline is expressed as the Go escape \n so the source file
	// remains valid UTF-8 text and is not treated as binary by git.
	maliciousURL := "http://evil.com/\n[FAKE] Admin logged in as root"

	req := postForm(map[string]string{
		"name":    "repo",
		"git_url": maliciousURL,
	})
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() { h.CreateRepo(rr, req) })

	// 1. The server must reject the non-whitelisted URL.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", rr.Code)
	}

	// 2. The forged message must NOT appear as a standalone log line.
	if strings.Contains(logOutput, "[FAKE] Admin logged in as root") {
		t.Error("log forging: injected newline produced a fake log entry — the %q fix is missing or ineffective")
	}

	// 3. The newline must be visibly escaped (as \\n) inside the quoted URL.
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("expected escaped newline (\\n) inside quoted URL in log; got: %q", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInjection verifies that \r is also
// escaped.  On terminals that render \r, an attacker can use it to overwrite
// the visible portion of a log line, hiding the real content.
func TestCreateRepo_LogForging_CarriageReturnInjection(t *testing.T) {
	h := newTestHandler(t)

	maliciousURL := "http://evil.com/\r[FAKE] Security alert dismissed"

	req := postForm(map[string]string{
		"name":    "repo",
		"git_url": maliciousURL,
	})
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() { h.CreateRepo(rr, req) })

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", rr.Code)
	}

	if strings.Contains(logOutput, "[FAKE] Security alert dismissed") {
		t.Error("log forging via \\r: carriage-return injection produced a fake log entry")
	}

	// %q escapes \r as \\r.
	if !strings.Contains(logOutput, `\r`) {
		t.Errorf("expected escaped carriage-return (\\r) in log output; got: %q", logOutput)
	}
}

// TestCreateRepo_LogForging_CombinedControlChars tests a payload that
// combines multiple control characters to maximise forgery impact.
func TestCreateRepo_LogForging_CombinedControlChars(t *testing.T) {
	h := newTestHandler(t)

	// \r\n is the CRLF sequence used in HTTP/SMTP log injection.
	maliciousURL := "http://evil.com/\r\n[AUTH] Password reset for admin"

	req := postForm(map[string]string{
		"name":    "repo",
		"git_url": maliciousURL,
	})
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() { h.CreateRepo(rr, req) })

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", rr.Code)
	}

	if strings.Contains(logOutput, "[AUTH] Password reset for admin") {
		t.Error("log forging via CRLF: injected CRLF produced a fake log entry")
	}
}

// TestCreateRepo_LogForging_URLQuotedInLog verifies the positive case: that
// a benign non-whitelisted URL is still logged, and appears enclosed in
// double-quotes (the hallmark of %q formatting).
func TestCreateRepo_LogForging_URLQuotedInLog(t *testing.T) {
	h := newTestHandler(t)

	safeURL := "https://bitbucket.org/org/repo.git"

	req := postForm(map[string]string{
		"name":    "repo",
		"git_url": safeURL,
	})
	rr := httptest.NewRecorder()

	logOutput := captureLog(func() { h.CreateRepo(rr, req) })

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want 400 for non-whitelisted domain, got %d", rr.Code)
	}

	// The URL must appear double-quoted in the log output (result of %q).
	quoted := `"` + safeURL + `"`
	if !strings.Contains(logOutput, quoted) {
		t.Errorf("expected URL to be quoted in log as %s; got: %s", quoted, logOutput)
	}
}

// ---------------------------------------------------------------------------
// Functional / handler behaviour tests
// ---------------------------------------------------------------------------

// TestCreateRepo_MethodNotAllowed ensures non-POST methods are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: want 405, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingRequiredFields verifies that requests lacking name or
// git_url are rejected with 400.
func TestCreateRepo_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		label  string
		fields map[string]string
	}{
		{"missing name", map[string]string{"git_url": "https://github.com/org/repo"}},
		{"missing git_url", map[string]string{"name": "my-repo"}},
		{"missing both", map[string]string{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			h := newTestHandler(t)
			req := postForm(tc.fields)
			rr := httptest.NewRecorder()
			h.CreateRepo(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status: want 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain checks that URLs on non-approved hosts
// produce a 400 with the expected error message.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)

	req := postForm(map[string]string{
		"name":    "repo",
		"git_url": "https://bitbucket.org/org/repo.git",
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "whitelisted") {
		t.Errorf("body should mention whitelist; got: %s", rr.Body.String())
	}
}

// TestCreateRepo_WhitelistedDomain_Success exercises the full success path:
// a valid, whitelisted URL is accepted and a JSON response with success=true
// and a positive id is returned.
func TestCreateRepo_WhitelistedDomain_Success(t *testing.T) {
	h := newTestHandler(t)

	req := postForm(map[string]string{
		"name":    "my-repo",
		"git_url": "https://github.com/org/repo.git",
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	id, ok := resp["id"].(float64)
	if !ok || id < 1 {
		t.Errorf("expected id >= 1, got %v", resp["id"])
	}
}

// TestCreateRepo_DefaultRepoType verifies that omitting repo_type from the
// form falls back to the default value "git" without error.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h := newTestHandler(t)

	// No repo_type field — handler should default to "git".
	req := postForm(map[string]string{
		"name":    "default-type-repo",
		"git_url": "https://github.com/org/another.git",
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// TestListRepos_EmptyDatabase verifies that listing repos on an empty database
// returns a JSON array (possibly empty) and a 200 status.
func TestListRepos_EmptyDatabase(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	h.ListRepos(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d", rr.Code)
	}

	var repos []interface{}
	if err := json.NewDecoder(rr.Body).Decode(&repos); err != nil {
		t.Fatalf("response is not valid JSON array: %v", err)
	}
}

// TestListRepos_MethodNotAllowed ensures that POST to /list is rejected.
func TestListRepos_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	h.ListRepos(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status: want 405, got %d", rr.Code)
	}
}
