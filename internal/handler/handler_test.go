package handler

import (
	"bytes"
	"database/sql"
	"fmt"
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

// setupTestHandler creates an in-memory SQLite DB and returns a Handler for testing.
func setupTestHandler(t *testing.T) *Handler {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory sqlite: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE repos (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		name      TEXT NOT NULL,
		git_url   TEXT NOT NULL,
		repo_type TEXT NOT NULL DEFAULT 'git',
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		t.Fatalf("failed to create test table: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// GitService is not called in CreateRepo; pass a no-op instance.
	gitService := service.NewGitService(t.TempDir())

	return NewHandler(repoStore, validator, gitService)
}

// captureLog redirects the standard logger output during fn and returns all
// lines that were written.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil) // restore default (stderr)
	fn()
	return buf.String()
}

// ---------------------------------------------------------------------------
// Log-forging regression tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInGitURL verifies that a newline character
// embedded in the git_url value cannot forge additional log lines.
// The %q verb in log.Printf must escape \n so it appears as the literal
// two-character sequence \n, not as a real newline.
func TestCreateRepo_LogForging_NewlineInGitURL(t *testing.T) {
	h := setupTestHandler(t)

	// Attacker-controlled value: embeds a fake log entry after a newline.
	maliciousURL := "https://github.com/user/repo\n[SECURITY] Admin password reset by root"

	form := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(w, req)
	})

	// The forged log entry must NOT appear as its own line.
	if strings.Contains(logOutput, "[SECURITY] Admin password reset by root") {
		t.Errorf("log forging succeeded: forged content appeared as a distinct log entry in:\n%s", logOutput)
	}

	// The URL (including the injected payload) must be quoted — i.e. the raw
	// newline must be escaped so it cannot split the log line.
	if strings.Contains(logOutput, "\n[SECURITY]") {
		t.Errorf("raw newline found in log output, forged line is present:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_CRLFInGitURL verifies that CRLF sequences are
// escaped by %q and cannot forge log lines.
func TestCreateRepo_LogForging_CRLFInGitURL(t *testing.T) {
	h := setupTestHandler(t)

	maliciousURL := "https://github.com/user/repo\r\n[AUDIT] Privilege escalation detected"

	form := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(w, req)
	})

	if strings.Contains(logOutput, "[AUDIT] Privilege escalation detected") {
		t.Errorf("CRLF log forging succeeded: forged content appeared as a distinct log entry:\n%s", logOutput)
	}
	if strings.Contains(logOutput, "\r\n[AUDIT]") {
		t.Errorf("raw CRLF found in log output, enabling forged line:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_TabAndControlChars checks that other control
// characters are escaped by %q and do not corrupt the log stream.
func TestCreateRepo_LogForging_TabAndControlChars(t *testing.T) {
	h := setupTestHandler(t)

	maliciousURL := "https://github.com/user/repo\t\x00\x1b[1mINJECTED\x1b[0m"

	form := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(w, req)
	})

	// Raw tab, null byte, or ANSI escape must not appear literally in the log.
	if strings.ContainsRune(logOutput, '\t') {
		// A tab from the logger prefix (timestamp) is acceptable, but a tab
		// within the quoted URL field is not. We check that the raw value is
		// not present after the "[VALIDATION]" label.
		if idx := strings.Index(logOutput, "[VALIDATION]"); idx != -1 {
			segment := logOutput[idx:]
			if strings.ContainsRune(segment, '\t') {
				t.Errorf("raw tab character found in log segment after [VALIDATION]: %q", segment)
			}
		}
	}
	if strings.ContainsRune(logOutput, '\x00') {
		t.Errorf("null byte found in log output: %q", logOutput)
	}
}

// TestCreateRepo_LogForging_RejectedURL verifies that the rejection log entry
// (line 52 in handler.go) also escapes newlines via %q.
func TestCreateRepo_LogForging_RejectedURL(t *testing.T) {
	h := setupTestHandler(t)

	// Domain is NOT whitelisted — rejection path is exercised.
	maliciousURL := "https://evil.example.com/repo\n[SECURITY] Login succeeded for admin"

	form := url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(w, req)
	})

	if strings.Contains(logOutput, "[SECURITY] Login succeeded for admin") {
		t.Errorf("log forging in rejection path: forged entry visible in log:\n%s", logOutput)
	}
	if strings.Contains(logOutput, "\n[SECURITY]") {
		t.Errorf("raw newline splits the rejection log line:\n%s", logOutput)
	}

	// The response should indicate failure.
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Positive / functional tests
// ---------------------------------------------------------------------------

// TestCreateRepo_ValidGitHubURL ensures a normal GitHub URL is accepted and
// the log output contains the URL wrapped in quotes (as produced by %q).
func TestCreateRepo_ValidGitHubURL(t *testing.T) {
	h := setupTestHandler(t)

	validURL := "https://github.com/user/repo"

	form := url.Values{
		"name":    {"my-repo"},
		"git_url": {validURL},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	logOutput := captureLog(func() {
		h.CreateRepo(w, req)
	})

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid URL, got %d; body: %s", w.Code, w.Body.String())
	}

	// The URL must appear quoted (surrounded by double-quotes) in the log,
	// confirming %q is in use.
	quotedURL := fmt.Sprintf("%q", validURL)
	if !strings.Contains(logOutput, quotedURL) {
		t.Errorf("expected log to contain quoted URL %s, got:\n%s", quotedURL, logOutput)
	}
}

// TestCreateRepo_ValidGitLabURL ensures a GitLab URL is also accepted.
func TestCreateRepo_ValidGitLabURL(t *testing.T) {
	h := setupTestHandler(t)

	form := url.Values{
		"name":    {"gitlab-repo"},
		"git_url": {"https://gitlab.com/group/project"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CreateRepo(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid GitLab URL, got %d", w.Code)
	}
}

// TestCreateRepo_MissingFields verifies that missing required fields return 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	h := setupTestHandler(t)

	tests := []struct {
		name string
		form url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/user/repo"}}},
		{"missing git_url", url.Values{"name": {"test"}}},
		{"both missing", url.Values{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
				strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.CreateRepo(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

// TestCreateRepo_MethodNotAllowed ensures GET requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies rejection of arbitrary domains.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	h := setupTestHandler(t)

	form := url.Values{
		"name":    {"bad-repo"},
		"git_url": {"https://evil.example.com/repo"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", w.Code)
	}
}

// TestListRepos_EmptyDatabase verifies ListRepos returns an empty JSON array.
func TestListRepos_EmptyDatabase(t *testing.T) {
	h := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	w := httptest.NewRecorder()
	h.ListRepos(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "[]") {
		t.Errorf("expected empty JSON array, got: %s", body)
	}
}

// TestListRepos_MethodNotAllowed ensures POST to ListRepos is rejected.
func TestListRepos_MethodNotAllowed(t *testing.T) {
	h := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	w := httptest.NewRecorder()
	h.ListRepos(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Content-Security-Policy header tests (CWE-346)
// ---------------------------------------------------------------------------

// checkCSPHeader is a helper that asserts the Content-Security-Policy header is
// present and non-empty in the recorded response.
func checkCSPHeader(t *testing.T, w *httptest.ResponseRecorder, context string) {
	t.Helper()
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("%s: Content-Security-Policy header is missing from response", context)
	}
}

// TestCreateRepo_CSPHeaderPresent verifies that a successful CreateRepo response
// carries the Content-Security-Policy header (CWE-346 remediation).
func TestCreateRepo_CSPHeaderPresent(t *testing.T) {
	h := setupTestHandler(t)

	form := url.Values{
		"name":    {"csp-test-repo"},
		"git_url": {"https://github.com/user/repo"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CreateRepo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	checkCSPHeader(t, w, "CreateRepo success")
}

// TestCreateRepo_CSPHeaderOnBadRequest verifies that the CSP header is also
// returned on 400 responses (e.g. missing required fields).
func TestCreateRepo_CSPHeaderOnBadRequest(t *testing.T) {
	h := setupTestHandler(t)

	// Missing both name and git_url — should return 400.
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CreateRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	checkCSPHeader(t, w, "CreateRepo bad request")
}

// TestCreateRepo_CSPHeaderOnNonWhitelistedDomain verifies the CSP header is
// present when the domain is rejected by the validator.
func TestCreateRepo_CSPHeaderOnNonWhitelistedDomain(t *testing.T) {
	h := setupTestHandler(t)

	form := url.Values{
		"name":    {"csp-test"},
		"git_url": {"https://evil.example.com/repo"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CreateRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	checkCSPHeader(t, w, "CreateRepo non-whitelisted domain")
}

// TestListRepos_CSPHeaderPresent verifies that ListRepos responses include the
// Content-Security-Policy header.
func TestListRepos_CSPHeaderPresent(t *testing.T) {
	h := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	w := httptest.NewRecorder()

	h.ListRepos(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	checkCSPHeader(t, w, "ListRepos success")
}

// TestListRepos_CSPHeaderOnMethodNotAllowed verifies that the CSP header is
// returned even on 405 error responses from ListRepos.
func TestListRepos_CSPHeaderOnMethodNotAllowed(t *testing.T) {
	h := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	w := httptest.NewRecorder()

	h.ListRepos(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
	checkCSPHeader(t, w, "ListRepos method not allowed")
}

// TestCreateRepo_CSPHeaderValue verifies that the Content-Security-Policy header
// has a value that includes a restrictive default-src directive.
func TestCreateRepo_CSPHeaderValue(t *testing.T) {
	h := setupTestHandler(t)

	form := url.Values{
		"name":    {"csp-value-test"},
		"git_url": {"https://github.com/user/repo"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CreateRepo(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}
	// The policy must include a default-src directive to be meaningful.
	if !strings.Contains(csp, "default-src") {
		t.Errorf("CSP header %q does not contain a default-src directive", csp)
	}
}

// TestCreateRepo_XContentTypeOptionsHeader verifies that X-Content-Type-Options
// is set to prevent MIME-type sniffing attacks.
func TestCreateRepo_XContentTypeOptionsHeader(t *testing.T) {
	h := setupTestHandler(t)

	form := url.Values{
		"name":    {"xcto-test"},
		"git_url": {"https://github.com/user/repo"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.CreateRepo(w, req)

	xcto := w.Header().Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", xcto)
	}
}
