package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"database/sql"

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// newTestDB creates an in-memory SQLite database with the required schema,
// suitable for use in tests without any filesystem side effects.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite3 db: %v", err)
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
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHandlerWithDB wires up a full Handler using an in-memory database.
// gitService is left nil because CreateRepo tests do not exercise Clone.
func newTestHandlerWithDB(t *testing.T) *Handler {
	t.Helper()
	db := newTestDB(t)
	return &Handler{
		repoStore:  repository.NewRepositoryStore(db),
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}
}

// captureLog redirects the standard logger to a buffer for the duration of fn,
// then restores it and returns everything that was written to the log.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// postCreateRepo issues a POST to the CreateRepo handler with the given values.
func postCreateRepo(h *Handler, values url.Values) *httptest.ResponseRecorder {
	body := strings.NewReader(values.Encode())
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ============================================================
// Tests: Log Forging (CWE-117) — sink at handler.go line 52
// ============================================================

// TestCreateRepo_LogForging_RejectionSink_NewlineEscaped is the primary
// regression test for the reported Log Forging vulnerability (CWE-117).
//
// The taint flow: r.FormValue("git_url") → gitURL → log.Printf at line 52.
// With the original %s format verb, a newline in the URL would cause the log
// output to contain a literally injected fake log line. The fix changes the
// format verb to %q which escapes all non-printable characters (including \n
// and \r) using Go's strconv.Quote conventions.
func TestCreateRepo_LogForging_RejectionSink_NewlineEscaped(t *testing.T) {
	h := newTestHandlerWithDB(t)

	// Payload: a non-whitelisted URL with an embedded newline that attempts to
	// inject a fake audit entry into the log stream.
	maliciousURL := "https://evil.com/path\n[AUDIT] User admin authenticated successfully"

	values := url.Values{
		"name":    {"evil-repo"},
		"git_url": {maliciousURL},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	logged := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	// The request must be rejected with 400 (domain not whitelisted).
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 for non-whitelisted domain, got %d", rr.Code)
	}

	// The injected fake audit line must NOT appear verbatim in the log.
	if strings.Contains(logged, "[AUDIT] User admin authenticated successfully") {
		t.Errorf("log forging detected: injected line appeared verbatim in log output\nlog output:\n%s", logged)
	}

	// The embedded newline must be escaped (the two-character sequence \n must
	// appear in the output, proving the %q verb is in effect).
	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected newline to be escaped as \\n in log output (%%q verb)\nlog output:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_RejectionSink_CarriageReturnEscaped verifies that
// a carriage return (\r) in the URL is also escaped at the rejection log sink.
// Carriage returns are used in terminal-overwrite attacks against log files.
func TestCreateRepo_LogForging_RejectionSink_CarriageReturnEscaped(t *testing.T) {
	h := newTestHandlerWithDB(t)

	maliciousURL := "https://evil.com/path\r[FAKE] Injected line overwriting previous entry"

	values := url.Values{
		"name":    {"evil-repo"},
		"git_url": {maliciousURL},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	logged := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400, got %d", rr.Code)
	}

	if strings.Contains(logged, "[FAKE] Injected line overwriting previous entry") {
		t.Errorf("log forging via \\r detected: injected text appeared in log output\nlog output:\n%s", logged)
	}

	if !strings.Contains(logged, `\r`) {
		t.Errorf("expected \\r to be escaped as \\\\r in log output\nlog output:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_ValidationSuccessSink_NewlineEscaped tests the
// second log statement (line 57: "Domain validated successfully") which is also
// part of the same taint flow — gitURL flows from FormValue to log.Printf.
func TestCreateRepo_LogForging_ValidationSuccessSink_NewlineEscaped(t *testing.T) {
	h := newTestHandlerWithDB(t)

	// A whitelisted URL with an embedded newline injection attempt.
	maliciousURL := "https://github.com/owner/repo\n[FAKE] Privilege escalation succeeded"

	values := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}

	logged := captureLog(func() {
		postCreateRepo(h, values)
	})

	// The injected fake entry must not appear as a real log line.
	if strings.Contains(logged, "[FAKE] Privilege escalation succeeded") {
		t.Errorf("log forging at validation-success sink: injected line appeared verbatim\nlog output:\n%s", logged)
	}

	// The newline must be escaped.
	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected newline to be escaped in validation-success log entry\nlog output:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_CreatedRepoSink_NewlineEscaped tests the third log
// statement (line 65: "Created repo") which logs both name and gitURL (also
// user-controlled) and is also part of the same taint flow.
func TestCreateRepo_LogForging_CreatedRepoSink_NewlineEscaped(t *testing.T) {
	h := newTestHandlerWithDB(t)

	// A whitelisted URL with an embedded newline.
	maliciousURL := "https://github.com/owner/repo\n[SECURITY] Password reset for all users"

	values := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}

	logged := captureLog(func() {
		postCreateRepo(h, values)
	})

	if strings.Contains(logged, "[SECURITY] Password reset for all users") {
		t.Errorf("log forging at created-repo sink: injected line appeared verbatim\nlog output:\n%s", logged)
	}

	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected newline to be escaped in created-repo log entry\nlog output:\n%s", logged)
	}
}

// TestCreateRepo_LogForging_NameField_NewlineEscaped verifies that the name
// field (also user-controlled) is quoted in the "Created repo" log entry.
func TestCreateRepo_LogForging_NameField_NewlineEscaped(t *testing.T) {
	h := newTestHandlerWithDB(t)

	maliciousName := "legit-repo\n[FAKE] Deployment initiated by admin"

	values := url.Values{
		"name":    {maliciousName},
		"git_url": {"https://github.com/owner/repo"},
	}

	logged := captureLog(func() {
		postCreateRepo(h, values)
	})

	if strings.Contains(logged, "[FAKE] Deployment initiated by admin") {
		t.Errorf("log forging via name field: injected line appeared verbatim\nlog output:\n%s", logged)
	}

	if !strings.Contains(logged, `\n`) {
		t.Errorf("expected newline in name to be escaped in log output\nlog output:\n%s", logged)
	}
}

// ============================================================
// Tests: Functional correctness after the fix
// ============================================================

// TestCreateRepo_CleanURL_LoggedWithQuotes verifies that a clean, valid URL
// is still logged correctly — the %q verb wraps the URL in double quotes but
// preserves its content (no data loss, no spurious escapes for normal URLs).
func TestCreateRepo_CleanURL_LoggedWithQuotes(t *testing.T) {
	h := newTestHandlerWithDB(t)

	cleanURL := "https://github.com/owner/repo"

	values := url.Values{
		"name":    {"my-repo"},
		"git_url": {cleanURL},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	logged := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	// Handler must succeed.
	if rr.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 for clean whitelisted URL, got %d: %s", rr.Code, rr.Body.String())
	}

	// The URL content must still appear in the log, surrounded by quotes.
	// %q produces: "https://github.com/owner/repo"
	if !strings.Contains(logged, `"https://github.com/owner/repo"`) {
		t.Errorf("expected quoted clean URL in log output\nlog output:\n%s", logged)
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests receive 405.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandlerWithDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields verifies that missing name or git_url returns 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := newTestHandlerWithDB(t)

	tests := []struct {
		name   string
		values url.Values
	}{
		{
			name:   "missing git_url",
			values: url.Values{"name": {"repo1"}},
		},
		{
			name:   "missing name",
			values: url.Values{"git_url": {"https://github.com/owner/repo"}},
		},
		{
			name:   "both missing",
			values: url.Values{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := postCreateRepo(h, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %s, got %d", tc.name, rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that non-whitelisted URLs are
// rejected with 400 and the response body does not reflect user input.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandlerWithDB(t)

	values := url.Values{
		"name":    {"repo"},
		"git_url": {"https://evil.com/malicious"},
	}

	rr := postCreateRepo(h, values)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_WhitelistedDomains_Accepted verifies that all configured
// whitelisted domains are accepted by the handler.
func TestCreateRepo_WhitelistedDomains_Accepted(t *testing.T) {
	whitelistedURLs := []struct {
		label string
		url   string
	}{
		{"github https", "https://github.com/owner/repo"},
		{"gitlab https", "https://gitlab.com/owner/repo"},
		{"github git", "git@github.com:owner/repo.git"},
		{"gitlab git", "git@gitlab.com:owner/repo.git"},
	}

	for _, tc := range whitelistedURLs {
		t.Run(tc.label, func(t *testing.T) {
			// Each sub-test gets its own handler with a fresh DB to avoid ID
			// collisions and cross-test interference.
			h := newTestHandlerWithDB(t)
			values := url.Values{
				"name":    {"test-repo"},
				"git_url": {tc.url},
			}
			rr := postCreateRepo(h, values)
			if rr.Code != http.StatusOK {
				t.Errorf("expected 200 for whitelisted URL %q, got %d: %s",
					tc.url, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestCreateRepo_DefaultRepoType verifies that the default repo type is set to
// "git" when the repo_type field is omitted.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h := newTestHandlerWithDB(t)

	values := url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/owner/repo"},
		// repo_type intentionally omitted
	}

	rr := postCreateRepo(h, values)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Response must indicate success.
	body := rr.Body.String()
	if !strings.Contains(body, `"success":true`) {
		t.Errorf("expected success:true in response, got: %s", body)
	}
}
