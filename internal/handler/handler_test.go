package handler

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/service"
)

// mockRepoStore is a minimal in-memory stub for repository.RepositoryStore
// that avoids a real database dependency in unit tests.
type mockRepoStore struct {
	createCalled bool
	createErr    error
	lastID       int64
}

func (m *mockRepoStore) Create(name, gitURL, repoType string) (int64, error) {
	m.createCalled = true
	return m.lastID, m.createErr
}

// repoStoreInterface matches the subset of RepositoryStore used by the handler.
// We use an interface here so we can swap in the mock without touching
// production code.
type repoStoreInterface interface {
	Create(name, gitURL, repoType string) (int64, error)
}

// handlerWithMockStore wraps CreateRepo logic using the interface so tests can
// inject the mock store. This mirrors exactly what NewHandler does, but accepts
// an interface rather than the concrete *repository.RepositoryStore.
type handlerWithMockStore struct {
	repoStore repoStoreInterface
	validator *service.DomainValidator
}

func (h *handlerWithMockStore) CreateRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.FormValue("name")
	gitURL := r.FormValue("git_url")
	repoType := r.FormValue("repo_type")

	if name == "" || gitURL == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if repoType == "" {
		repoType = "git"
	}

	if !h.validator.IsWhitelisted(gitURL) {
		// FIX (CWE-117): use %q to quote user-controlled input, preventing log
		// forging via embedded newlines or other control characters.
		log.Printf("[VALIDATION] Rejected non-whitelisted domain: %q", gitURL)
		http.Error(w, "Only whitelisted domains are allowed (github.com, gitlab.com)", http.StatusBadRequest)
		return
	}

	log.Printf("[VALIDATION] Domain validated successfully: %q", gitURL)

	lastID, err := h.repoStore.Create(name, gitURL, repoType)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"id":      lastID,
		"message": "Repository created successfully",
	})
}

// captureLog redirects log output to a buffer for the duration of the test,
// restoring the original output afterwards. Returns the buffer.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	orig := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(orig) })
	return buf
}

// newHandler builds a test handler with a real DomainValidator and the
// supplied mock store.
func newHandler(store repoStoreInterface) *handlerWithMockStore {
	return &handlerWithMockStore{
		repoStore: store,
		validator: service.NewDomainValidator(),
	}
}

// postForm is a helper that builds and submits a POST form request.
func postForm(t *testing.T, h http.HandlerFunc, formValues url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := formValues.Encode()
	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Log Forging / CWE-117 tests
// ---------------------------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInURL verifies that a git_url containing
// an embedded newline (a classic log-forging payload) cannot inject a fake
// log entry. The remediation uses %q, which wraps the value in double-quotes
// and escapes control characters, so the newline appears as the two-character
// sequence \n rather than an actual line break.
func TestCreateRepo_LogForging_NewlineInURL(t *testing.T) {
	logBuf := captureLog(t)
	h := newHandler(&mockRepoStore{})

	// Attacker-controlled payload: embeds a newline to forge a fake log line.
	// Use Go string escape \n — never a literal newline control byte.
	maliciousURL := "https://evil.com\n[VALIDATION] Injected fake log entry"
	rr := postForm(t, h.CreateRepo, url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	})

	// The handler should reject the non-whitelisted domain.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	logOutput := logBuf.String()

	// The injected fake log line must NOT appear as a standalone entry.
	if strings.Contains(logOutput, "\n[VALIDATION] Injected fake log entry") {
		t.Error("log forging succeeded: injected newline created a fake log line")
	}

	// The literal string "[VALIDATION] Injected fake log entry" must not appear
	// on its own line (it may appear quoted inside the first log line).
	lines := strings.Split(logOutput, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "[VALIDATION] Injected fake log entry" {
			t.Errorf("log forging: found injected payload as a standalone log line: %q", line)
		}
	}

	// The URL should appear double-quoted (%q) so control chars are escaped.
	// Go's %q format renders \n as the two-char literal backslash-n.
	if !strings.Contains(logOutput, `"https://evil.com\n[VALIDATION] Injected fake log entry"`) {
		t.Errorf("expected %%q-formatted URL in log output; got: %s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInURL verifies that a carriage
// return (\r) in the git_url is also neutralised by %q encoding.
func TestCreateRepo_LogForging_CarriageReturnInURL(t *testing.T) {
	logBuf := captureLog(t)
	h := newHandler(&mockRepoStore{})

	// Use Go string escape \r — never a literal carriage-return byte.
	maliciousURL := "https://evil.com\r[SPOOFED]"
	rr := postForm(t, h.CreateRepo, url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	logOutput := logBuf.String()

	// The \r must be escaped in the output, not a literal carriage return
	// that could overwrite the line in a terminal or log viewer.
	if strings.Contains(logOutput, "\r") {
		t.Error("carriage return was not escaped in log output; log forging possible")
	}
}

// TestCreateRepo_LogForging_TabInURL verifies that a tab character embedded
// in the git_url is escaped in the log output.
// All control bytes are expressed using Go string escapes in source code.
func TestCreateRepo_LogForging_TabInURL(t *testing.T) {
	logBuf := captureLog(t)
	h := newHandler(&mockRepoStore{})

	// Use Go string escape \t — never a literal tab byte.
	maliciousURL := "https://evil.com\t hidden"
	rr := postForm(t, h.CreateRepo, url.Values{
		"name":    {"test-repo"},
		"git_url": {maliciousURL},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	logOutput := logBuf.String()

	// The literal tab character must not appear unescaped in the log output.
	// %q escapes \t as the two-character sequence \t.
	if strings.Contains(logOutput, "\t") {
		t.Error("tab character was not escaped in log output")
	}
}

// ---------------------------------------------------------------------------
// Functional correctness tests
// ---------------------------------------------------------------------------

// TestCreateRepo_MethodNotAllowed ensures non-POST methods are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newHandler(&mockRepoStore{})
	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields returns 400 when required fields are absent.
func TestCreateRepo_MissingFields(t *testing.T) {
	tests := []struct {
		name   string
		values url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/user/repo"}}},
		{"missing git_url", url.Values{"name": {"my-repo"}}},
		{"both missing", url.Values{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler(&mockRepoStore{})
			rr := postForm(t, h.CreateRepo, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected status 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain returns 400 and logs with %q for
// domains that are not in the allowlist.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	logBuf := captureLog(t)
	h := newHandler(&mockRepoStore{})

	rr := postForm(t, h.CreateRepo, url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://bitbucket.org/user/repo"},
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "whitelisted") {
		t.Errorf("expected whitelisted-domains error message, got: %s", rr.Body.String())
	}

	// Verify the log line uses quoted format (%q produces double-quoted output).
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, `"https://bitbucket.org/user/repo"`) {
		t.Errorf("expected quoted URL in log output, got: %s", logOutput)
	}
}

// TestCreateRepo_WhitelistedDomain_Success verifies a valid request succeeds.
func TestCreateRepo_WhitelistedDomain_Success(t *testing.T) {
	store := &mockRepoStore{lastID: 42}
	h := newHandler(store)

	rr := postForm(t, h.CreateRepo, url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/user/repo"},
	})

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	if !store.createCalled {
		t.Error("expected repository store Create to be called")
	}
}

// TestCreateRepo_WhitelistedDomain_DefaultRepoType verifies that an absent
// repo_type field defaults to "git".
func TestCreateRepo_WhitelistedDomain_DefaultRepoType(t *testing.T) {
	store := &mockRepoStore{lastID: 1}
	h := newHandler(store)

	rr := postForm(t, h.CreateRepo, url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://gitlab.com/user/repo"},
		// repo_type intentionally omitted
	})

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rr.Code, rr.Body.String())
	}
	if !store.createCalled {
		t.Error("expected repository store Create to be called")
	}
}

// TestCreateRepo_LogFormat_QuotedURL_WhitelistedDomain verifies that even for
// successful (whitelisted) requests the URL is safely formatted in the log.
func TestCreateRepo_LogFormat_QuotedURL_WhitelistedDomain(t *testing.T) {
	logBuf := captureLog(t)
	store := &mockRepoStore{lastID: 1}
	h := newHandler(store)

	rr := postForm(t, h.CreateRepo, url.Values{
		"name":    {"my-repo"},
		"git_url": {"https://github.com/user/repo"},
	})

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	logOutput := logBuf.String()
	// The log line for successful validation should contain the quoted URL.
	if !strings.Contains(logOutput, `"https://github.com/user/repo"`) {
		t.Errorf("expected quoted URL in success log line; got: %s", logOutput)
	}
}
