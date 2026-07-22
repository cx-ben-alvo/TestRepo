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

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"

	// Use the pure Go SQLite driver so tests don't require CGo.
	_ "github.com/mattn/go-sqlite3"
)

// openTestDB creates an in-memory SQLite database and initialises the schema.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE repos (
		id       INTEGER PRIMARY KEY AUTOINCREMENT,
		name     TEXT    NOT NULL,
		git_url  TEXT    NOT NULL,
		repo_type TEXT   NOT NULL DEFAULT 'git',
		created  DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		db.Close()
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHandler returns a Handler wired to an in-memory database.
// gitService is nil because the clone path is not exercised in these tests.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db := openTestDB(t)
	store := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	return NewHandler(store, validator, nil)
}

// captureLog redirects the default logger output to a buffer for the duration
// of the test and returns the buffer so callers can inspect what was logged.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	origFlags := log.Flags()
	log.SetFlags(0)        // omit timestamp so comparisons are deterministic
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(nil) // restore to os.Stderr
		log.SetFlags(origFlags)
	})
	return buf
}

// postForm is a helper that fires a POST request against h.CreateRepo with the
// given form values and returns the recorded response.
func postForm(h *Handler, values url.Values) *httptest.ResponseRecorder {
	body := strings.NewReader(values.Encode())
	req := httptest.NewRequest(http.MethodPost, "/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Log-forging regression tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInjection verifies that a git_url containing
// an embedded newline – the primary log-forging vector – does NOT appear as a
// raw newline in the audit log entry.  The %q format verb in the handler must
// escape the newline so it becomes \n in the log output.
func TestCreateRepo_LogForging_NewlineInjection(t *testing.T) {
	h := newTestHandler(t)
	logBuf := captureLog(t)

	// Craft a URL that passes the whitelist check (contains "github.com") but
	// also embeds a newline followed by a fake log entry.
	// The newline is written as the escape sequence \n – never as a literal
	// control byte – to keep the source file reviewable.
	injectedURL := "https://github.com/evil\n[ADMIN] Password reset for admin"

	rr := postForm(h, url.Values{
		"name":    {"my-repo"},
		"git_url": {injectedURL},
	})

	// The handler may return 200 (domain whitelisted) or 400; in either case
	// the log must not contain the raw injected fake entry.
	_ = rr

	logOutput := logBuf.String()

	// The raw injected fake log line must NOT appear verbatim.
	if strings.Contains(logOutput, "[ADMIN] Password reset for admin") {
		t.Errorf("log forging succeeded: injected fake log entry appeared verbatim in log output.\nFull log:\n%s", logOutput)
	}

	// The newline character must NOT appear as a raw newline inside the
	// validation log line (it must be escaped to the two-character sequence \n).
	// We look for the escaped form "\\n" because %q turns \n into the literal
	// two characters backslash-n in the output.
	if strings.Contains(logOutput, "[VALIDATION] Domain validated successfully:") {
		// Extract the validation line and verify the newline is escaped.
		for _, line := range strings.Split(logOutput, "\n") {
			if strings.Contains(line, "[VALIDATION] Domain validated successfully:") {
				if !strings.Contains(line, `\n`) {
					t.Errorf("newline in git_url was NOT escaped in the log line.\nLog line: %q", line)
				}
				break
			}
		}
	}
}

// TestCreateRepo_LogForging_CarriageReturnInjection verifies that a carriage
// return (\r) is also escaped, preventing CRLF-based log manipulation.
func TestCreateRepo_LogForging_CarriageReturnInjection(t *testing.T) {
	h := newTestHandler(t)
	logBuf := captureLog(t)

	// URL that passes the whitelist but contains \r followed by a fake entry.
	injectedURL := "https://github.com/repo\r[FAKE] Injected entry"

	rr := postForm(h, url.Values{
		"name":    {"my-repo"},
		"git_url": {injectedURL},
	})
	_ = rr

	logOutput := logBuf.String()

	if strings.Contains(logOutput, "[FAKE] Injected entry") {
		t.Errorf("log forging via CR succeeded: fake entry appeared verbatim.\nFull log:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_QuotedOutput confirms that the validation log
// message uses %q-style quoting (output starts and ends with a double-quote
// character) for the git_url field, which is the mechanism that prevents
// injection.
func TestCreateRepo_LogForging_QuotedOutput(t *testing.T) {
	h := newTestHandler(t)
	logBuf := captureLog(t)

	validURL := "https://github.com/user/repo"

	rr := postForm(h, url.Values{
		"name":    {"my-repo"},
		"git_url": {validURL},
	})

	// Expect 200 for a whitelisted URL.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for whitelisted URL, got %d", rr.Code)
	}

	logOutput := logBuf.String()

	// The %q verb wraps the value in double-quotes.  Verify the log line
	// contains the quoted URL rather than the bare URL.
	quotedURL := `"` + validURL + `"`
	if !strings.Contains(logOutput, quotedURL) {
		t.Errorf("expected log to contain quoted URL %s, but got:\n%s", quotedURL, logOutput)
	}
}

// ---------------------------------------------------------------------------
// Functional tests (ensure the fix does not break normal behaviour)
// ---------------------------------------------------------------------------

// TestCreateRepo_ValidRequest verifies that a well-formed POST with a
// whitelisted git_url returns HTTP 200 and a JSON success response.
func TestCreateRepo_ValidRequest(t *testing.T) {
	h := newTestHandler(t)
	_ = captureLog(t) // suppress log noise in test output

	rr := postForm(h, url.Values{
		"name":    {"test-repo"},
		"git_url": {"https://github.com/user/test-repo"},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Errorf("expected JSON success response, got: %s", rr.Body.String())
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a non-whitelisted domain
// is rejected with HTTP 400 and that the rejection message does NOT include the
// raw user-supplied URL in a way that could expose injected content.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)
	_ = captureLog(t)

	rr := postForm(h, url.Values{
		"name":    {"bad-repo"},
		"git_url": {"https://evil.example.com/payload"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields return
// HTTP 400 without panicking.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := newTestHandler(t)
	_ = captureLog(t)

	cases := []struct {
		name   string
		values url.Values
	}{
		{
			name:   "missing git_url",
			values: url.Values{"name": {"repo"}},
		},
		{
			name:   "missing name",
			values: url.Values{"git_url": {"https://github.com/user/repo"}},
		},
		{
			name:   "missing both",
			values: url.Values{},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rr := postForm(h, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected HTTP 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_WrongMethod verifies that non-POST methods are rejected with
// HTTP 405.
func TestCreateRepo_WrongMethod(t *testing.T) {
	h := newTestHandler(t)
	_ = captureLog(t)

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected HTTP 405, got %d", rr.Code)
	}
}

// TestCreateRepo_DefaultRepoType verifies that repo_type defaults to "git"
// when not provided in the form.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h := newTestHandler(t)
	_ = captureLog(t)

	rr := postForm(h, url.Values{
		"name":    {"default-type-repo"},
		"git_url": {"https://github.com/user/default-type-repo"},
		// repo_type intentionally omitted
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
}
