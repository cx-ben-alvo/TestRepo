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

// newTestHandler sets up an in-memory SQLite database and returns a Handler
// suitable for use in unit tests.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name      TEXT NOT NULL,
		git_url   TEXT NOT NULL,
		repo_type TEXT NOT NULL DEFAULT 'git',
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// gitService is not exercised by CreateRepo, so pass nil.
	return NewHandler(repoStore, validator, nil)
}

// captureLog redirects log output to a buffer for the duration of fn.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil) // restore default (stderr)
	fn()
	return buf.String()
}

// postForm issues a POST request with the provided form values and returns the
// ResponseRecorder and captured log output.
func postForm(h *Handler, values url.Values) (*httptest.ResponseRecorder, string) {
	body := strings.NewReader(values.Encode())
	req := httptest.NewRequest(http.MethodPost, "/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	var logOutput string
	logOutput = captureLog(func() {
		h.CreateRepo(rr, req)
	})
	return rr, logOutput
}

// ---------------------------------------------------------------------------
// Tests for Log Forging fix (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInURL verifies that a git_url containing an
// embedded newline cannot forge additional log lines.  The %q verb must escape
// \n so that the log entry stays on a single logical line.
func TestCreateRepo_LogForging_NewlineInURL(t *testing.T) {
	h := newTestHandler(t)

	// Craft a URL that embeds a newline followed by a fake log entry.
	// If log forging were possible, the injected text would appear as a
	// separate log line in the output.
	maliciousURL := "https://github.com/user/repo\n[SECURITY] Admin login successful for root"

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {maliciousURL},
	}

	_, logOutput := postForm(h, values)

	// The injected payload must NOT appear as a raw newline in the log output.
	if strings.Contains(logOutput, "\n[SECURITY]") {
		t.Errorf("log forging detected: injected newline not escaped in log output:\n%s", logOutput)
	}

	// The %q verb must produce a quoted representation that contains the
	// escape sequence \\n (backslash-n) rather than an actual newline.
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("expected newline to be escaped as \\n in log output, got:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInURL verifies that \r is also
// escaped, preventing log-terminal forgery on systems that interpret CR.
func TestCreateRepo_LogForging_CarriageReturnInURL(t *testing.T) {
	h := newTestHandler(t)

	maliciousURL := "https://github.com/user/repo\r[FAKE] Overwritten log line"

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {maliciousURL},
	}

	_, logOutput := postForm(h, values)

	// The carriage return must be escaped, not passed through literally.
	if strings.Contains(logOutput, "\r[FAKE]") {
		t.Errorf("log forging detected: injected CR not escaped in log output:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, `\r`) {
		t.Errorf("expected carriage return to be escaped as \\r in log output, got:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_NameWithNewline verifies that the repo name field
// is also quoted with %q, preventing forging through the name parameter.
func TestCreateRepo_LogForging_NameWithNewline(t *testing.T) {
	h := newTestHandler(t)

	maliciousName := "legitimate-name\n[ALERT] Injected log entry"

	values := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/user/repo"},
	}

	_, logOutput := postForm(h, values)

	if strings.Contains(logOutput, "\n[ALERT]") {
		t.Errorf("log forging detected via name field: injected newline not escaped:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("expected newline in name to be escaped as \\n in log output, got:\n%s", logOutput)
	}
}

// ---------------------------------------------------------------------------
// Functional / regression tests
// ---------------------------------------------------------------------------

// TestCreateRepo_Success verifies that a valid POST creates a repository and
// returns a successful JSON response with an assigned ID.
func TestCreateRepo_Success(t *testing.T) {
	h := newTestHandler(t)

	values := url.Values{
		"name":      {"my-repo"},
		"git_url":   {"https://github.com/user/repo"},
		"repo_type": {"git"},
	}

	rr, _ := postForm(h, values)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	if resp["id"] == nil {
		t.Error("expected non-nil id in response")
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields return
// a 400 Bad Request.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name   string
		values url.Values
	}{
		{
			name:   "missing name",
			values: url.Values{"git_url": {"https://github.com/user/repo"}},
		},
		{
			name:   "missing git_url",
			values: url.Values{"name": {"my-repo"}},
		},
		{
			name:   "missing both",
			values: url.Values{},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rr, _ := postForm(h, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a URL from a non-allowed
// domain is rejected with a 400 Bad Request.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)

	values := url.Values{
		"name":    {"evil-repo"},
		"git_url": {"https://evil.example.com/malware"},
	}

	rr, _ := postForm(h, values)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST methods are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCreateRepo_DefaultRepoType verifies that repo_type defaults to "git"
// when not provided.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h := newTestHandler(t)

	values := url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/user/repo"},
		// repo_type intentionally omitted
	}

	rr, _ := postForm(h, values)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateRepo_LogOutput_SafeURL verifies that a clean URL is logged
// with surrounding double-quotes (the %q verb), allowing consumers to
// distinguish the quoted value from the rest of the log message.
func TestCreateRepo_LogOutput_SafeURL(t *testing.T) {
	h := newTestHandler(t)

	values := url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/user/repo"},
	}

	_, logOutput := postForm(h, values)

	// The %q verb wraps the value in double-quotes.
	if !strings.Contains(logOutput, `"https://github.com/user/repo"`) {
		t.Errorf("expected url to appear quoted in log output, got:\n%s", logOutput)
	}
}
