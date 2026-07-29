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

// newTestDB creates an in-memory SQLite database for testing.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name      TEXT    NOT NULL,
		git_url   TEXT    NOT NULL,
		repo_type TEXT    NOT NULL DEFAULT 'git',
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

// newTestHandler wires up a Handler backed by an in-memory database.
func newTestHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()
	db := newTestDB(t)
	store := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	h := NewHandler(store, validator, nil) // gitService not needed for CreateRepo
	return h, db
}

// captureLog redirects the default logger output to a buffer and returns it.
// The caller must invoke the returned restore function when done.
func captureLog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	flags := log.Flags()
	prefix := log.Prefix()
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(buf)
	restore := func() {
		log.SetOutput(nil) // reset to stderr
		log.SetFlags(flags)
		log.SetPrefix(prefix)
	}
	return buf, restore
}

// postForm sends a POST request with the given form values to the handler.
func postForm(t *testing.T, h *Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Functional tests
// ---------------------------------------------------------------------------

// TestCreateRepo_Success verifies that a valid repository creation request
// succeeds and returns the expected JSON response.
func TestCreateRepo_Success(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{
		"name":      {"my-repo"},
		"git_url":   {"https://github.com/example/repo.git"},
		"repo_type": {"git"},
	}

	rr := postForm(t, h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	if resp["id"] == nil {
		t.Error("expected non-nil id in response")
	}
}

// TestCreateRepo_DefaultRepoType checks that omitting repo_type defaults to "git".
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{
		"name":    {"default-type-repo"},
		"git_url": {"https://github.com/example/default.git"},
	}
	rr := postForm(t, h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields are rejected.
func TestCreateRepo_MissingFields(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	cases := []struct {
		name string
		form url.Values
	}{
		{
			name: "missing name",
			form: url.Values{"git_url": {"https://github.com/example/repo.git"}},
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

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := postForm(t, h, tc.form)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain checks that URLs from non-whitelisted
// domains are rejected.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{
		"name":    {"evil-repo"},
		"git_url": {"https://evil.com/attacker/repo.git"},
	}
	rr := postForm(t, h, form)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Log forging / log injection security tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInRepoType ensures that a user-supplied
// repo_type containing newline characters does not inject extra lines into
// the log output.  The fix uses %q in log.Printf so that the value is
// quoted and special characters are escaped.
func TestCreateRepo_LogForging_NewlineInRepoType(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	// An attacker-controlled value containing a newline intended to forge a
	// fake log entry.
	maliciousRepoType := "git\n[REPO] Created repo ID=99, name=\"hacked\", url=\"https://github.com/evil/repo\""

	form := url.Values{
		"name":      {"legit-repo"},
		"git_url":   {"https://github.com/example/legit.git"},
		"repo_type": {maliciousRepoType},
	}

	logBuf, restore := captureLog(t)
	defer restore()

	rr := postForm(t, h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logged := logBuf.String()

	// The forged log entry must NOT appear as a separate, unescaped line.
	if strings.Contains(logged, "[REPO] Created repo ID=99") {
		t.Errorf("log forging succeeded: forged entry found in log output:\n%s", logged)
	}

	// The raw newline from the attacker payload must not appear unescaped
	// inside a [REPO] log line; %q escapes it as \\n.
	lines := strings.Split(logged, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "[REPO]") {
			if strings.Contains(line, "\n") {
				t.Errorf("log line contains unescaped newline: %q", line)
			}
		}
	}
}

// TestCreateRepo_LogForging_NewlineInName ensures that a user-supplied name
// containing a newline character is quoted/escaped in the log output.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	maliciousName := "legit\n[SECURITY] Auth bypass succeeded"

	form := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/example/repo.git"},
	}

	logBuf, restore := captureLog(t)
	defer restore()

	rr := postForm(t, h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	logged := logBuf.String()
	if strings.Contains(logged, "[SECURITY] Auth bypass succeeded") {
		t.Errorf("log forging via name field succeeded:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_NewlineInGitURL ensures that a user-supplied
// git_url containing a newline character is quoted/escaped in the log output.
func TestCreateRepo_LogForging_NewlineInGitURL(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	// Use a URL that passes domain validation but carries a newline payload.
	maliciousURL := "https://github.com/example/repo.git\n[REPO] Created repo ID=1337, name=\"backdoor\""

	form := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}

	logBuf, restore := captureLog(t)
	defer restore()

	rr := postForm(t, h, form)
	// The request may be rejected by domain validation (the URL contains a newline
	// so it might not match).  Either way the forged log line must not appear.
	_ = rr

	logged := logBuf.String()
	if strings.Contains(logged, "[REPO] Created repo ID=1337") {
		t.Errorf("log forging via git_url field succeeded:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInRepoType ensures that carriage
// returns are also escaped, as they can manipulate terminal display.
func TestCreateRepo_LogForging_CarriageReturnInRepoType(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	// \r can overwrite the previous log line on a terminal.
	maliciousRepoType := "git\r[REPO] Created repo ID=0, name=\"overwritten\""

	form := url.Values{
		"name":      {"cr-test"},
		"git_url":   {"https://github.com/example/repo.git"},
		"repo_type": {maliciousRepoType},
	}

	logBuf, restore := captureLog(t)
	defer restore()

	rr := postForm(t, h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	logged := logBuf.String()

	// Confirm the raw carriage return does not appear unescaped in the REPO log line.
	for _, line := range strings.Split(logged, "\n") {
		if strings.HasPrefix(line, "[REPO]") && strings.ContainsRune(line, '\r') {
			t.Errorf("log line contains unescaped carriage return: %q", line)
		}
	}
}

// TestCreateRepo_LogFormat_QuotedValues verifies that legitimate values are
// still logged correctly and that the %q format does not break the message.
func TestCreateRepo_LogFormat_QuotedValues(t *testing.T) {
	h, db := newTestHandler(t)
	defer db.Close()

	form := url.Values{
		"name":      {"my-project"},
		"git_url":   {"https://github.com/example/my-project.git"},
		"repo_type": {"git"},
	}

	logBuf, restore := captureLog(t)
	defer restore()

	rr := postForm(t, h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	logged := logBuf.String()

	// The log must contain a [REPO] line with the repository name quoted.
	if !strings.Contains(logged, "[REPO]") {
		t.Errorf("expected [REPO] log line, got:\n%s", logged)
	}
	// With %q, the name appears as "my-project" (double-quoted).
	if !strings.Contains(logged, `"my-project"`) {
		t.Errorf("expected quoted name in log, got:\n%s", logged)
	}
}
