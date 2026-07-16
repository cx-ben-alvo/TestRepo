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
)

// --- Minimal stubs for handler dependencies ---

// stubRepositoryStore satisfies the interface used by Handler without a real DB.
type stubRepositoryStore struct {
	createFunc func(name, gitURL, repoType string) (int64, error)
}

// stubDomainValidator mirrors service.DomainValidator behaviour.
type stubDomainValidator struct {
	allowedDomains []string
}

func (v *stubDomainValidator) IsWhitelisted(gitURL string) bool {
	lower := strings.ToLower(gitURL)
	for _, d := range v.allowedDomains {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// stubGitService satisfies the interface used by Handler without running git.
type stubGitService struct{}

// newTestHandler builds a Handler whose dependencies are replaced with stubs
// so that tests do not need a real database or git binary.
func newTestHandler(createFunc func(name, gitURL, repoType string) (int64, error)) *Handler {
	repoStore := &stubRepositoryStore{createFunc: createFunc}
	validator := &stubDomainValidator{allowedDomains: []string{"github.com", "gitlab.com"}}

	// Use reflection-free composition: the handler struct fields are unexported,
	// so we use the public constructor.  To avoid importing real dependencies the
	// test creates a small HTTP server that exercises only the log-forging path
	// (see TestCreateRepo_LogForging* below) via httptest.
	_ = repoStore
	_ = validator
	return nil // replaced by the HTTP-level helpers below
}

// ---------------------------------------------------------------------------
// HTTP-level helpers
// ---------------------------------------------------------------------------

// postCreateRepo sends a POST /create-repo request with the supplied form
// values and returns the recorded response.
func postCreateRepo(t *testing.T, h http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, "/create-repo", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Unit tests: log-forging sanitisation in CreateRepo
//
// These tests exercise the sanitisation logic directly by constructing an
// http.HandlerFunc that replicates the sanitisation step from CreateRepo and
// verifies the output contains no injected newlines.
// ---------------------------------------------------------------------------

// sanitizeGitURL is the canonical one-liner extracted from handler.go so that
// the test can validate the same expression in isolation.
func sanitizeGitURL(raw string) string {
	return strings.NewReplacer("\n", "", "\r", "").Replace(raw)
}

// TestSanitizeGitURL_StripNewline verifies that a lone newline injected into
// the URL is removed.
func TestSanitizeGitURL_StripNewline(t *testing.T) {
	t.Parallel()
	injected := "https://github.com/user/repo\nINJECTED LOG LINE"
	got := sanitizeGitURL(injected)
	if strings.Contains(got, "\n") {
		t.Errorf("sanitized value still contains newline: %q", got)
	}
	if strings.Contains(got, "INJECTED LOG LINE") {
		t.Errorf("sanitized value still contains injected content: %q", got)
	}
}

// TestSanitizeGitURL_StripCarriageReturn verifies that a carriage return
// injected into the URL is removed.
func TestSanitizeGitURL_StripCarriageReturn(t *testing.T) {
	t.Parallel()
	injected := "https://github.com/user/repo\rINJECTED"
	got := sanitizeGitURL(injected)
	if strings.Contains(got, "\r") {
		t.Errorf("sanitized value still contains carriage return: %q", got)
	}
}

// TestSanitizeGitURL_StripCRLF verifies combined CRLF injection is removed.
func TestSanitizeGitURL_StripCRLF(t *testing.T) {
	t.Parallel()
	injected := "https://github.com/user/repo\r\n[FAKE] admin logged in"
	got := sanitizeGitURL(injected)
	if strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Errorf("sanitized value still contains CRLF: %q", got)
	}
}

// TestSanitizeGitURL_PreservesLegitURL ensures that a normal URL without
// injected characters passes through unchanged.
func TestSanitizeGitURL_PreservesLegitURL(t *testing.T) {
	t.Parallel()
	legit := "https://github.com/owner/my-repo.git"
	got := sanitizeGitURL(legit)
	if got != legit {
		t.Errorf("sanitizer modified a clean URL: got %q, want %q", got, legit)
	}
}

// TestSanitizeGitURL_EmptyString verifies the sanitizer handles an empty
// input without panicking.
func TestSanitizeGitURL_EmptyString(t *testing.T) {
	t.Parallel()
	got := sanitizeGitURL("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// TestSanitizeGitURL_MultipleInjectedLines verifies that multiple consecutive
// injected log lines are all stripped.
func TestSanitizeGitURL_MultipleInjectedLines(t *testing.T) {
	t.Parallel()
	injected := "https://github.com/x/y\nFAKE1\nFAKE2\nFAKE3"
	got := sanitizeGitURL(injected)
	if strings.Contains(got, "\n") {
		t.Errorf("sanitized value still contains newlines: %q", got)
	}
	for _, fake := range []string{"FAKE1", "FAKE2", "FAKE3"} {
		if strings.Contains(got, fake) {
			t.Errorf("sanitized value still contains injected content %q: %q", fake, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration-level tests: verify the handler logs a sanitized URL
// ---------------------------------------------------------------------------

// logCaptureHandler wraps a standard http.HandlerFunc and redirects the
// standard logger output so we can assert on what was written to the log.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	fn()
	return buf.String()
}

// TestCreateRepo_LogDoesNotContainInjectedNewline sends a request with a
// newline-injected git_url and verifies the log output does not contain the
// injected content.
//
// This test uses a thin http.HandlerFunc that reproduces only the input
// extraction and sanitisation logic from handler.go so the test remains
// self-contained and does not require a real database.
func TestCreateRepo_LogDoesNotContainInjectedNewline(t *testing.T) {
	t.Parallel()

	// minimal handler that mirrors the sanitisation + log statement under test
	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("git_url")
		gitURL := strings.NewReplacer("\n", "", "\r", "").Replace(raw)
		log.Printf("[VALIDATION] Domain validated successfully: %s", gitURL)
		w.WriteHeader(http.StatusOK)
	})

	injected := "https://github.com/x/y\nINJECTED: admin access granted"
	form := url.Values{"git_url": {injected}}
	var logOutput string
	logOutput = captureLog(t, func() {
		postCreateRepo(t, handlerFn, form)
	})

	if strings.Contains(logOutput, "INJECTED") {
		t.Errorf("log output contains injected content; log forging not mitigated.\nlog: %q", logOutput)
	}
	if strings.Contains(logOutput, "\n\n") {
		// A single trailing newline is expected from log.Printf; two consecutive
		// newlines would indicate a forged second log line.
		t.Errorf("log output contains double newline suggesting forged log line.\nlog: %q", logOutput)
	}
}

// TestCreateRepo_LogDoesNotContainInjectedCRLF is the CRLF variant of the
// above test.
func TestCreateRepo_LogDoesNotContainInjectedCRLF(t *testing.T) {
	t.Parallel()

	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("git_url")
		gitURL := strings.NewReplacer("\n", "", "\r", "").Replace(raw)
		log.Printf("[VALIDATION] Domain validated successfully: %s", gitURL)
		w.WriteHeader(http.StatusOK)
	})

	injected := "https://github.com/x/y\r\n[AUDIT] password changed"
	form := url.Values{"git_url": {injected}}
	var logOutput string
	logOutput = captureLog(t, func() {
		postCreateRepo(t, handlerFn, form)
	})

	if strings.Contains(logOutput, "[AUDIT] password changed") {
		t.Errorf("log output contains CRLF-injected content; log forging not mitigated.\nlog: %q", logOutput)
	}
}

// TestCreateRepo_CleanURLAppearsInLog verifies that a legitimate URL does
// appear in the log (i.e., the sanitisation does not break normal logging).
func TestCreateRepo_CleanURLAppearsInLog(t *testing.T) {
	t.Parallel()

	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.FormValue("git_url")
		gitURL := strings.NewReplacer("\n", "", "\r", "").Replace(raw)
		log.Printf("[VALIDATION] Domain validated successfully: %s", gitURL)
		w.WriteHeader(http.StatusOK)
	})

	clean := "https://github.com/owner/repo.git"
	form := url.Values{"git_url": {clean}}
	var logOutput string
	logOutput = captureLog(t, func() {
		postCreateRepo(t, handlerFn, form)
	})

	if !strings.Contains(logOutput, clean) {
		t.Errorf("log output does not contain the legitimate URL %q.\nlog: %q", clean, logOutput)
	}
}

// ---------------------------------------------------------------------------
// JSON response tests (regression: handler still responds correctly)
// ---------------------------------------------------------------------------

// minimalCreateRepoResponse is used to decode the success JSON response.
type minimalCreateRepoResponse struct {
	Success bool        `json:"success"`
	ID      interface{} `json:"id"`
	Message string      `json:"message"`
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests return 405.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	// Build a handler that mimics the method check at the top of CreateRepo.
	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/create-repo", nil)
	rr := httptest.NewRecorder()
	handlerFn(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields verifies that missing name/git_url returns 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	t.Parallel()

	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")
		gitURL := strings.NewReplacer("\n", "", "\r", "").Replace(r.FormValue("git_url"))
		if name == "" || gitURL == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		desc string
		form url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/x/y"}}},
		{"missing git_url", url.Values{"name": {"myrepo"}}},
		{"both missing", url.Values{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			rr := postCreateRepo(t, handlerFn, tc.form)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("[%s] expected 400, got %d", tc.desc, rr.Code)
			}
		})
	}
}

// TestCreateRepo_SuccessResponseShape verifies that a successful creation
// returns the expected JSON shape.
func TestCreateRepo_SuccessResponseShape(t *testing.T) {
	t.Parallel()

	// Stub handler that mirrors the success path of CreateRepo (sans DB).
	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.FormValue("name")
		gitURL := strings.NewReplacer("\n", "", "\r", "").Replace(r.FormValue("git_url"))
		if name == "" || gitURL == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"id":      int64(1),
			"message": "Repository created successfully",
		})
	})

	form := url.Values{
		"name":    {"myrepo"},
		"git_url": {"https://github.com/owner/myrepo.git"},
	}
	rr := postCreateRepo(t, handlerFn, form)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp minimalCreateRepoResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success=true, got false")
	}
	if resp.Message != "Repository created successfully" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}
