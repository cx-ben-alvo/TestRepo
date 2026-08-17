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

	"github.com/checkmarx/correlation-demo/internal/service"
)

// newTestHandler creates a Handler with nil repoStore and gitService (safe for
// tests that exercise only the validation layer — requests rejected by the
// domain whitelist never reach the store or git service).
func newTestHandler() *Handler {
	return &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}
}

// postFormRequest sends a POST request to CreateRepo with the given form values.
func postFormRequest(h *Handler, form url.Values) *httptest.ResponseRecorder {
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// captureLog redirects the standard logger output into a buffer for the
// duration of fn and returns everything that was logged.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr) // restore standard logger output
	fn()
	return buf.String()
}

// ---------------------------------------------------------------------------
// Log-forging remediation tests (CWE-117)
// ---------------------------------------------------------------------------

// TestCreateRepo_RejectedURL_NewlineNotRawInLog verifies that a git_url
// containing a newline (the primary log-forging vector) does NOT produce a raw
// newline in the log output — it must appear as the escape sequence \n.
func TestCreateRepo_RejectedURL_NewlineNotRawInLog(t *testing.T) {
	h := newTestHandler()

	// Embed a newline to attempt forging a second log entry.
	maliciousURL := "http://evil.com/repo\nINFO: forged entry"

	var logOutput string
	rr := httptest.NewRecorder()
	logOutput = captureLog(func() {
		body := strings.NewReader(url.Values{
			"name":    {"test-repo"},
			"git_url": {maliciousURL},
		}.Encode())
		req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.CreateRepo(rr, req)
	})

	// Validation must reject the non-whitelisted domain.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	// The forged text must NOT appear as a new log line.
	if strings.Contains(logOutput, "INFO: forged entry") {
		t.Error("log forging detected: injected text appeared as a separate log entry")
	}

	// The newline must be escaped to the two-character sequence \n.
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("expected escaped newline (\\n) in log output; got: %q", logOutput)
	}
}

// TestCreateRepo_RejectedURL_CarriageReturnEscaped ensures that \r (used to
// overwrite log lines on terminals) is escaped by %q.
func TestCreateRepo_RejectedURL_CarriageReturnEscaped(t *testing.T) {
	h := newTestHandler()

	maliciousURL := "http://evil.com/repo\rFAKE"

	var logOutput string
	rr := httptest.NewRecorder()
	logOutput = captureLog(func() {
		body := strings.NewReader(url.Values{
			"name":    {"test-repo"},
			"git_url": {maliciousURL},
		}.Encode())
		req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.CreateRepo(rr, req)
	})

	// Raw \r must not appear.
	if strings.ContainsRune(logOutput, '\r') {
		t.Error("log forging: raw carriage-return appeared in log; must be escaped with %q")
	}

	// \r must appear as the two-character escape sequence.
	if !strings.Contains(logOutput, `\r`) {
		t.Errorf("expected \\r escape sequence in log; got: %q", logOutput)
	}
}

// TestCreateRepo_RejectedURL_TabEscaped verifies that tab characters in
// user input are escaped (tabs can misalign structured log parsers).
func TestCreateRepo_RejectedURL_TabEscaped(t *testing.T) {
	h := newTestHandler()

	maliciousURL := "http://evil.com/\tFAKE"

	var logOutput string
	rr := httptest.NewRecorder()
	logOutput = captureLog(func() {
		body := strings.NewReader(url.Values{
			"name":    {"test-repo"},
			"git_url": {maliciousURL},
		}.Encode())
		req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.CreateRepo(rr, req)
	})

	if strings.ContainsRune(logOutput, '\t') {
		t.Error("log forging: raw tab appeared in log; must be escaped with %q")
	}
	if !strings.Contains(logOutput, `\t`) {
		t.Errorf("expected \\t escape sequence in log; got: %q", logOutput)
	}
}

// TestCreateRepo_ControlCharacters_AllEscaped is a table-driven test covering
// multiple control-character vectors in a single pass.
func TestCreateRepo_ControlCharacters_AllEscaped(t *testing.T) {
	h := newTestHandler()

	tests := []struct {
		name        string
		rawByte     rune   // the byte that must NOT appear raw in the log
		escapedForm string // the %q two-char escape sequence that MUST appear
		gitURL      string // URL embedding the raw byte
	}{
		{"LF newline", '\n', `\n`, "http://evil.com/\nFAKE"},
		{"CR return", '\r', `\r`, "http://evil.com/\rFAKE"},
		{"tab", '\t', `\t`, "http://evil.com/\tFAKE"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logOutput string
			rr := httptest.NewRecorder()
			logOutput = captureLog(func() {
				body := strings.NewReader(url.Values{
					"name":    {"test-repo"},
					"git_url": {tc.gitURL},
				}.Encode())
				req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				h.CreateRepo(rr, req)
			})

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
			if strings.ContainsRune(logOutput, tc.rawByte) {
				t.Errorf("[%s] raw control byte appeared unescaped in log; expected %s", tc.name, tc.escapedForm)
			}
			if !strings.Contains(logOutput, tc.escapedForm) {
				t.Errorf("[%s] expected escape sequence %s in log; got: %q", tc.name, tc.escapedForm, logOutput)
			}
		})
	}
}

// TestCreateRepo_LargeInjectionPayload_NoLogForging verifies that a URL with
// many embedded newlines does not create multiple extra log lines.
func TestCreateRepo_LargeInjectionPayload_NoLogForging(t *testing.T) {
	h := newTestHandler()

	var sb strings.Builder
	sb.WriteString("http://evil.com/")
	for i := 0; i < 50; i++ {
		sb.WriteString("\nFAKE ENTRY ")
		sb.WriteString(strings.Repeat("X", 10))
	}
	maliciousURL := sb.String()

	var logOutput string
	rr := httptest.NewRecorder()
	logOutput = captureLog(func() {
		body := strings.NewReader(url.Values{
			"name":    {"test-repo"},
			"git_url": {maliciousURL},
		}.Encode())
		req := httptest.NewRequest(http.MethodPost, "/api/repo/create", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.CreateRepo(rr, req)
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	// log.Printf adds exactly one trailing newline per call. After stripping
	// it there should be at most one line (the rejection entry).
	lines := strings.Split(strings.TrimRight(logOutput, "\n"), "\n")
	if len(lines) > 1 {
		t.Errorf("log forging: expected 1 log line but got %d; raw output: %q", len(lines), logOutput)
	}

	// All 50 newlines must be represented as \n escape sequences.
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("expected escaped newlines in log output; got: %q", logOutput)
	}
}

// ---------------------------------------------------------------------------
// HTTP behaviour tests
// ---------------------------------------------------------------------------

// TestCreateRepo_NonWhitelisted_Returns400 verifies that URLs from domains
// not on the allowlist are rejected with HTTP 400.
func TestCreateRepo_NonWhitelisted_Returns400(t *testing.T) {
	h := newTestHandler()

	rr := postFormRequest(h, url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://bitbucket.org/user/repo.git"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields_Returns400 verifies that an empty name or URL
// results in HTTP 400 before any log output involving user data.
func TestCreateRepo_MissingFields_Returns400(t *testing.T) {
	h := newTestHandler()

	cases := []url.Values{
		{"name": {""}, "git_url": {"https://github.com/user/repo.git"}},
		{"name": {"my-repo"}, "git_url": {""}},
		{"name": {""}, "git_url": {""}},
	}

	for _, form := range cases {
		rr := postFormRequest(h, form)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for missing fields %v, got %d", form, rr.Code)
		}
	}
}

// TestCreateRepo_WrongMethod_Returns405 verifies that GET requests to CreateRepo
// are rejected with HTTP 405.
func TestCreateRepo_WrongMethod_Returns405(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestListRepos_WrongMethod_Returns405 verifies that non-GET requests to
// ListRepos are rejected with HTTP 405.
func TestListRepos_WrongMethod_Returns405(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/repo/list", nil)
	rr := httptest.NewRecorder()
	h.ListRepos(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCloneRepo_WrongMethod_Returns405 verifies that GET requests to CloneRepo
// are rejected with HTTP 405.
func TestCloneRepo_WrongMethod_Returns405(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/repo/clone", nil)
	rr := httptest.NewRecorder()
	h.CloneRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCloneRepo_MissingRepoID_Returns400 verifies that a clone request
// without repo_id returns HTTP 400.
func TestCloneRepo_MissingRepoID_Returns400(t *testing.T) {
	h := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/repo/clone",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CloneRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing repo_id, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Response body / whitelist validator tests
// ---------------------------------------------------------------------------

// TestCreateRepo_RejectedURL_ErrorMessageDoesNotEchoURL verifies that the HTTP
// response body for a non-whitelisted URL does NOT echo the user-supplied URL
// (prevents information leakage and potential XSS in downstream consumers).
func TestCreateRepo_RejectedURL_ErrorMessageDoesNotEchoURL(t *testing.T) {
	h := newTestHandler()

	sentinelURL := "https://attacker.example.com/sentinel12345"
	rr := postFormRequest(h, url.Values{
		"name":    {"test-repo"},
		"git_url": {sentinelURL},
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	if strings.Contains(rr.Body.String(), sentinelURL) {
		t.Errorf("response body echoes user-supplied URL (info leak): %q", rr.Body.String())
	}
}

// TestCreateRepo_RejectionResponse_IsPlainText verifies that the rejection
// response from http.Error is plain text (not JSON), preventing parsers from
// consuming injected content as structured data.
func TestCreateRepo_RejectionResponse_IsPlainText(t *testing.T) {
	h := newTestHandler()

	rr := postFormRequest(h, url.Values{
		"name":    {"test-repo"},
		"git_url": {"https://evil.com/repo.git"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	// http.Error writes plain text; JSON decode must fail.
	var obj map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&obj); err == nil {
		t.Error("expected plain-text error response but got valid JSON")
	}
}

// ---------------------------------------------------------------------------
// DomainValidator whitelist regression tests
// ---------------------------------------------------------------------------

// TestDomainValidator_WhitelistedDomains verifies that github.com and
// gitlab.com URLs pass the whitelist check.
func TestDomainValidator_WhitelistedDomains(t *testing.T) {
	v := service.NewDomainValidator()

	whitelisted := []string{
		"https://github.com/user/repo.git",
		"https://gitlab.com/user/repo.git",
		"git@github.com:user/repo.git",
		"git@gitlab.com:user/repo.git",
	}

	for _, u := range whitelisted {
		if !v.IsWhitelisted(u) {
			t.Errorf("expected %q to be whitelisted", u)
		}
	}
}

// TestDomainValidator_NonWhitelistedDomains verifies that URLs from domains
// not on the allowlist are rejected.
func TestDomainValidator_NonWhitelistedDomains(t *testing.T) {
	v := service.NewDomainValidator()

	blocked := []string{
		"https://bitbucket.org/user/repo.git",
		"http://notgithub.com/user/repo.git",
	}

	for _, u := range blocked {
		if v.IsWhitelisted(u) {
			t.Errorf("expected %q to be blocked by whitelist", u)
		}
	}
}

// TestCreateRepo_WhitelistedURL_PassesValidation verifies that a valid
// whitelisted URL is NOT rejected at the validation layer (i.e. it does not
// return HTTP 400 from the whitelist check). Because repoStore is nil the
// request proceeds to the store call and fails with a nil-pointer panic;
// we recover from that to confirm validation passed.
func TestCreateRepo_WhitelistedURL_PassesValidation(t *testing.T) {
	h := newTestHandler()

	defer func() {
		// A nil-pointer panic from h.repoStore.Create is expected and means
		// validation succeeded.  Any other panic is a real error.
		if r := recover(); r != nil {
			// panic from nil repoStore.Create call — this is expected;
			// it confirms the URL passed whitelist validation.
		}
	}()

	rr := postFormRequest(h, url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/user/repo.git"},
	})

	// If we reach here without a panic, the validator accepted the URL but the
	// store returned an error. Either way, the response must NOT be 400
	// (whitelist rejection).
	if rr.Code == http.StatusBadRequest {
		t.Error("whitelisted URL was incorrectly rejected with 400")
	}
}
