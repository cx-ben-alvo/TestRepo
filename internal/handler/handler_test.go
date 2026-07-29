package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/models"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// stubRepoStore is a minimal in-memory substitute for *repository.RepositoryStore
// used exclusively in tests to avoid requiring a real SQLite database.
// It satisfies the repoCreator interface defined in handler.go.
type stubRepoStore struct {
	createFunc func(name, gitURL, repoType string) (int64, error)
}

func (s *stubRepoStore) Create(name, gitURL, repoType string) (int64, error) {
	if s.createFunc != nil {
		return s.createFunc(name, gitURL, repoType)
	}
	return 1, nil
}

func (s *stubRepoStore) GetByID(_ int) (*models.Repository, error) {
	return nil, nil
}

func (s *stubRepoStore) List() ([]*models.Repository, error) {
	return nil, nil
}

// handlerWithStub constructs a Handler whose repoStore field is satisfied by
// stubRepoStore.  The validator is the real service.DomainValidator so that
// domain-allowlist logic is exercised honestly.
func handlerWithStub(stub *stubRepoStore) *Handler {
	return &Handler{
		repoStore: stub,
		validator: service.NewDomainValidator(),
	}
}

// captureLog redirects the default logger to a buffer for the duration of fn,
// then restores it to os.Stderr.  Returns the captured output.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	fn()
	return buf.String()
}

// postCreateRepo fires a POST /create-repo request with the supplied form values
// and returns the recorded response.
func postCreateRepo(h *Handler, values url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/create-repo", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// --- Log Forging Tests -------------------------------------------------------

// TestCreateRepo_LogForging_NewlineInGitURL verifies that a newline injected
// into the git_url field cannot forge a second log entry.  With %q the newline
// is rendered as the two-character sequence \n rather than a literal newline,
// so the output still contains exactly one log record after the injection.
func TestCreateRepo_LogForging_NewlineInGitURL(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	injectedURL := "https://github.com/user/repo\n[FORGED] admin login successful"

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {injectedURL},
	}

	logOutput := captureLog(func() {
		postCreateRepo(h, values)
	})

	// The literal newline must NOT appear as an actual newline in the logged URL.
	// With %q it will appear as the escaped sequence \n inside double quotes.
	if strings.Contains(logOutput, "[FORGED]") {
		t.Errorf("Log forging attack succeeded: log output contains injected content\n%s", logOutput)
	}

	// The escaped form \\n should appear (Go %q escapes \n → \\n in the output)
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("Expected escaped newline (\\n) in log output, got:\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInGitURL verifies that \r is also
// escaped, preventing terminal/log viewer tricks on Windows-style line endings.
func TestCreateRepo_LogForging_CarriageReturnInGitURL(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	injectedURL := "https://github.com/user/repo\r[OVERRIDE]"

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {injectedURL},
	}

	logOutput := captureLog(func() {
		postCreateRepo(h, values)
	})

	if strings.Contains(logOutput, "[OVERRIDE]") {
		t.Errorf("Log forging via \\r succeeded: log output contains injected content\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_NewlineInName verifies the name field (also
// user-controlled) is similarly protected against log injection.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	injectedName := "myrepo\n[INJECTED] privilege escalation"

	values := url.Values{
		"name":    {injectedName},
		"git_url": {"https://github.com/user/repo"},
	}

	logOutput := captureLog(func() {
		postCreateRepo(h, values)
	})

	if strings.Contains(logOutput, "[INJECTED]") {
		t.Errorf("Log forging via name field succeeded: log output contains injected content\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_RejectedURL_NoInjection verifies that the
// rejection log path (domain not whitelisted) also escapes the URL.
func TestCreateRepo_LogForging_RejectedURL_NoInjection(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	// Not in the allowlist, so the validator will reject it — but the URL still
	// gets logged at the rejection site.
	injectedURL := "https://evil.com/repo\n[AUDIT] root login"

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {injectedURL},
	}

	logOutput := captureLog(func() {
		rr := postCreateRepo(h, values)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
		}
	})

	if strings.Contains(logOutput, "[AUDIT]") {
		t.Errorf("Log forging at rejection path succeeded: log output contains injected content\n%s", logOutput)
	}
}

// TestCreateRepo_LogForging_NullByteInGitURL verifies that a null byte
// (written as the escape sequence \x00) is also properly quoted.
func TestCreateRepo_LogForging_NullByteInGitURL(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	injectedURL := "https://github.com/user/repo\x00hidden"

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {injectedURL},
	}

	logOutput := captureLog(func() {
		postCreateRepo(h, values)
	})

	// The null byte should be escaped (as \x00) in quoted output, not raw.
	if strings.Contains(logOutput, "\x00") {
		t.Errorf("Null byte appeared raw in log output; %q was not applied", injectedURL)
	}
}

// --- Functional (non-regression) Tests ---------------------------------------

// TestCreateRepo_ValidRequest verifies normal success path still works.
func TestCreateRepo_ValidRequest(t *testing.T) {
	stub := &stubRepoStore{
		createFunc: func(name, gitURL, repoType string) (int64, error) {
			return 42, nil
		},
	}
	h := handlerWithStub(stub)

	values := url.Values{
		"name":      {"my-project"},
		"git_url":   {"https://github.com/user/repo"},
		"repo_type": {"git"},
	}

	rr := postCreateRepo(h, values)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if success, ok := resp["success"].(bool); !ok || !success {
		t.Errorf("expected success=true in response, got %v", resp)
	}

	if id, ok := resp["id"].(float64); !ok || id != 42 {
		t.Errorf("expected id=42 in response, got %v", resp["id"])
	}
}

// TestCreateRepo_MissingFields verifies that missing name/git_url returns 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	cases := []struct {
		name   string
		values url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/user/repo"}}},
		{"missing git_url", url.Values{"name": {"myrepo"}}},
		{"missing both", url.Values{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := postCreateRepo(h, tc.values)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
		})
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	req := httptest.NewRequest(http.MethodGet, "/create-repo", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that an unknown domain returns 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	stub := &stubRepoStore{}
	h := handlerWithStub(stub)

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {"https://bitbucket.org/user/repo"},
	}

	rr := postCreateRepo(h, values)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_WhitelistedDomains verifies that the known-good domains pass
// the validator (functional regression guard).
func TestCreateRepo_WhitelistedDomains(t *testing.T) {
	stub := &stubRepoStore{
		createFunc: func(_, _, _ string) (int64, error) { return 1, nil },
	}
	h := handlerWithStub(stub)

	validURLs := []string{
		"https://github.com/user/repo",
		"https://gitlab.com/user/repo",
		"git@github.com:user/repo.git",
		"git@gitlab.com:user/repo.git",
	}

	for _, u := range validURLs {
		t.Run(u, func(t *testing.T) {
			values := url.Values{
				"name":    {"myrepo"},
				"git_url": {u},
			}
			rr := postCreateRepo(h, values)
			if rr.Code != http.StatusOK {
				t.Errorf("expected 200 for whitelisted URL %q, got %d: %s", u, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestCreateRepo_DatabaseError verifies that a store error returns 500.
func TestCreateRepo_DatabaseError(t *testing.T) {
	stub := &stubRepoStore{
		createFunc: func(_, _, _ string) (int64, error) {
			return 0, fmt.Errorf("connection refused")
		},
	}
	h := handlerWithStub(stub)

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {"https://github.com/user/repo"},
	}

	rr := postCreateRepo(h, values)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// TestCreateRepo_DefaultRepoType verifies that an omitted repo_type defaults to "git".
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	var capturedType string
	stub := &stubRepoStore{
		createFunc: func(_, _, repoType string) (int64, error) {
			capturedType = repoType
			return 1, nil
		},
	}
	h := handlerWithStub(stub)

	values := url.Values{
		"name":    {"myrepo"},
		"git_url": {"https://github.com/user/repo"},
		// repo_type intentionally omitted
	}

	postCreateRepo(h, values)

	if capturedType != "git" {
		t.Errorf("expected default repo_type 'git', got %q", capturedType)
	}
}
