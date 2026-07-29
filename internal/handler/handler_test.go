package handler

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/database"
	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// newTestHandler creates a Handler backed by an in-memory SQLite database
// suitable for unit tests.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	db, err := database.InitDB()
	if err != nil {
		t.Fatalf("failed to init test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// GitService is not exercised by CreateRepo, so a zero-value works.
	gitSvc := service.NewGitService(t.TempDir())

	return NewHandler(repoStore, validator, gitSvc)
}

// postForm submits a POST form request to the handler and returns the recorder.
func postForm(h *Handler, fields map[string]string) *httptest.ResponseRecorder {
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}

	req := httptest.NewRequest(http.MethodPost, "/repos", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// captureLog redirects the standard logger output during fn and returns what
// was emitted.  This is used to verify that log entries do not contain raw
// user-supplied newlines (log-forging prevention).
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr) // restore default
	fn()
	return buf.String()
}

// ---------------------------------------------------------------------------
// CreateRepo – happy-path tests
// ---------------------------------------------------------------------------

func TestCreateRepo_Success(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(h, map[string]string{
		"name":    "my-repo",
		"git_url": "https://github.com/owner/repo",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode response: %v", err)
	}
	if success, _ := resp["success"].(bool); !success {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	if _, ok := resp["id"]; !ok {
		t.Error("expected 'id' field in response")
	}
}

// ---------------------------------------------------------------------------
// Log-Forging (CWE-117) prevention tests
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInURL verifies that a git_url containing
// an embedded newline does NOT produce a fake injected log entry.
// With the fixed format verb (%q), the newline is represented as the two-
// character escape \n rather than a real newline, preventing a log-forging
// attack where an attacker could inject a fabricated log line.
func TestCreateRepo_LogForging_NewlineInURL(t *testing.T) {
	h := newTestHandler(t)

	// Payload contains a newline followed by a fake log entry an attacker
	// might try to inject.
	injectedLine := "INJECTED] Fake log entry by attacker"
	maliciousURL := "https://github.com/owner/repo\n[REPO] " + injectedLine

	logOutput := captureLog(t, func() {
		postForm(h, map[string]string{
			"name":    "attack-repo",
			"git_url": maliciousURL,
		})
	})

	// The log output must NOT contain the injected fake log line as a
	// standalone line.  With %q the newline is escaped to \n literal.
	if strings.Contains(logOutput, injectedLine) {
		t.Errorf("log forging detected: injected line appeared verbatim in log output.\nLog was:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInURL verifies that \r is also
// escaped by %q to prevent CRLF log injection.
func TestCreateRepo_LogForging_CarriageReturnInURL(t *testing.T) {
	h := newTestHandler(t)

	injectedLine := "INJECTED] Carriage-return forging attempt"
	maliciousURL := "https://github.com/owner/repo\r[REPO] " + injectedLine

	logOutput := captureLog(t, func() {
		postForm(h, map[string]string{
			"name":    "crlf-repo",
			"git_url": maliciousURL,
		})
	})

	if strings.Contains(logOutput, injectedLine) {
		t.Errorf("CRLF log forging detected: injected line appeared in log output.\nLog was:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_QuotedOutput verifies that after a successful
// create the audit log line uses %q quoting (i.e. the URL appears wrapped
// in double-quotes and special characters are escaped).
func TestCreateRepo_LogForging_QuotedOutput(t *testing.T) {
	h := newTestHandler(t)

	gitURL := "https://github.com/owner/quoted-repo"

	logOutput := captureLog(t, func() {
		postForm(h, map[string]string{
			"name":    "quoted-repo",
			"git_url": gitURL,
		})
	})

	// The %q format surrounds the string with double-quotes.
	expectedQuoted := `"` + gitURL + `"`
	if !strings.Contains(logOutput, expectedQuoted) {
		t.Errorf("expected log to contain %q-formatted URL %s, but log was:\n%s", gitURL, expectedQuoted, logOutput)
	}
}

// ---------------------------------------------------------------------------
// Input validation tests
// ---------------------------------------------------------------------------

func TestCreateRepo_MissingName(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(h, map[string]string{
		"git_url": "https://github.com/owner/repo",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rr.Code)
	}
}

func TestCreateRepo_MissingGitURL(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(h, map[string]string{
		"name": "my-repo",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing git_url, got %d", rr.Code)
	}
}

func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(h, map[string]string{
		"name":    "evil-repo",
		"git_url": "https://evil.example.com/owner/repo",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/repos", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET request, got %d", rr.Code)
	}
}

func TestCreateRepo_DefaultRepoType(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(h, map[string]string{
		"name":    "default-type-repo",
		"git_url": "https://github.com/owner/repo",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if !resp["success"].(bool) {
		t.Error("expected success=true when repo_type is omitted")
	}
}

func TestCreateRepo_WhitelistedGitLabURL(t *testing.T) {
	h := newTestHandler(t)

	rr := postForm(h, map[string]string{
		"name":    "gitlab-repo",
		"git_url": "https://gitlab.com/owner/repo",
	})

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for whitelisted gitlab.com URL, got %d: %s", rr.Code, rr.Body.String())
	}
}
