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
	"os"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// newTestHandler builds a Handler backed by an in-memory SQLite database.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name      TEXT    NOT NULL,
		git_url   TEXT    NOT NULL,
		repo_type TEXT    NOT NULL DEFAULT 'git',
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	store := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// Use a temp directory for clones; these tests don't exercise the clone path.
	gitService := service.NewGitService(t.TempDir())

	return NewHandler(store, validator, gitService)
}

// captureLog redirects the default logger output into a buffer for the
// duration of a sub-test and returns it when the test finishes.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// postForm issues a POST request with the provided form values and returns
// the recorded response.
func postForm(t *testing.T, h *Handler, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Log-forging remediation tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogDoesNotContainRepoType verifies that user-supplied
// repo_type is NOT present in the audit log output after a successful
// repository creation.  The root cause of the log-forging finding was that
// the taint from r.FormValue("repo_type") flowed through repoStore.Create()
// into the log.Printf call.  The fix removes all user-controlled strings from
// that specific log statement, logging only the database-generated integer ID.
func TestCreateRepo_LogDoesNotContainRepoType(t *testing.T) {
	h := newTestHandler(t)
	buf := captureLog(t)

	injectedRepoType := "custom-type"
	rr := postForm(t, h, url.Values{
		"name":      {"myrepo"},
		"git_url":   {"https://github.com/example/repo"},
		"repo_type": {injectedRepoType},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, injectedRepoType) {
		t.Errorf("log-forging: audit log must NOT contain user-supplied repo_type %q; log was: %s",
			injectedRepoType, logOutput)
	}
}

// TestCreateRepo_LogForging_NewlineInjection ensures that a malicious
// repo_type value containing a newline (classic log-forging payload) cannot
// inject a fake log entry.  The log line after the fix must only contain the
// integer repo ID, so a newline in repo_type has no effect on the log.
func TestCreateRepo_LogForging_NewlineInjection(t *testing.T) {
	h := newTestHandler(t)
	buf := captureLog(t)

	// Payload that would forge a new log line if user input were interpolated.
	// The newline is expressed as \n (Go escape) – never a literal control byte.
	fakeLogEntry := "[SECURITY] admin login success"
	maliciousRepoType := "git\n" + fakeLogEntry

	rr := postForm(t, h, url.Values{
		"name":      {"evil-repo"},
		"git_url":   {"https://github.com/example/evil"},
		"repo_type": {maliciousRepoType},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, fakeLogEntry) {
		t.Errorf("log-forging: audit log must NOT contain injected fake entry %q; log was: %s",
			fakeLogEntry, logOutput)
	}
}

// TestCreateRepo_LogForging_CRLFInjection is the same test using a CRLF
// sequence – another common log-forging vector.
func TestCreateRepo_LogForging_CRLFInjection(t *testing.T) {
	h := newTestHandler(t)
	buf := captureLog(t)

	fakeLogEntry := "[AUDIT] privilege-escalation granted"
	// \r\n expressed as Go escape sequences – not literal bytes.
	maliciousRepoType := "git\r\n" + fakeLogEntry

	rr := postForm(t, h, url.Values{
		"name":      {"crlf-repo"},
		"git_url":   {"https://github.com/example/crlf"},
		"repo_type": {maliciousRepoType},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, fakeLogEntry) {
		t.Errorf("log-forging: audit log must NOT contain CRLF-injected entry %q; log was: %s",
			fakeLogEntry, logOutput)
	}
}

// TestCreateRepo_LogContainsGeneratedID verifies that the audit log still
// records the database-generated integer ID after the fix, so the log remains
// useful for audit purposes.
func TestCreateRepo_LogContainsGeneratedID(t *testing.T) {
	h := newTestHandler(t)
	buf := captureLog(t)

	rr := postForm(t, h, url.Values{
		"name":    {"id-check-repo"},
		"git_url": {"https://github.com/example/id-check"},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Parse the JSON response to get the database-generated ID.
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	idVal, ok := resp["id"]
	if !ok {
		t.Fatal("response missing 'id' field")
	}
	idFloat, ok := idVal.(float64)
	if !ok {
		t.Fatalf("'id' field is not a number: %T %v", idVal, idVal)
	}

	logOutput := buf.String()

	// The audit log must contain the "[REPO] Created repo ID=" prefix.
	if !strings.Contains(logOutput, "[REPO] Created repo ID=") {
		t.Errorf("audit log must contain '[REPO] Created repo ID=' for observability; log was: %s", logOutput)
	}

	// The specific numeric ID returned by the API must appear in the log.
	idStr := fmt.Sprintf("ID=%d", int64(idFloat))
	if !strings.Contains(logOutput, idStr) {
		t.Errorf("audit log must contain %q; log was: %s", idStr, logOutput)
	}
}

// ---------------------------------------------------------------------------
// Functional tests – verify CreateRepo still works correctly after the fix
// ---------------------------------------------------------------------------

// TestCreateRepo_Success checks that a valid repository creation returns HTTP
// 200 with the expected JSON fields.
func TestCreateRepo_Success(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(t, h, url.Values{
		"name":      {"testrepo"},
		"git_url":   {"https://github.com/example/test"},
		"repo_type": {"git"},
	})

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
	if _, hasID := resp["id"]; !hasID {
		t.Error("response must contain 'id' field")
	}
}

// TestCreateRepo_DefaultRepoType verifies that when repo_type is omitted the
// handler defaults to "git" and still returns a successful response.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(t, h, url.Values{
		"name":    {"notype-repo"},
		"git_url": {"https://github.com/example/notype"},
		// repo_type intentionally omitted
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields return
// HTTP 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := newTestHandler(t)

	cases := []struct {
		name   string
		values url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/x/y"}}},
		{"missing git_url", url.Values{"name": {"repo"}}},
		{"both missing", url.Values{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := postForm(t, h, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain ensures that repositories with a
// non-whitelisted git URL are rejected with HTTP 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(t, h, url.Values{
		"name":    {"evil"},
		"git_url": {"https://evil.example.com/repo"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MethodNotAllowed checks that non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}
