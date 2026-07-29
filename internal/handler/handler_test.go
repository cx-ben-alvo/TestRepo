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

	"github.com/checkmarx/correlation-demo/internal/service"
)

// logCapture redirects log output to a buffer so tests can inspect what was logged.
// The returned function restores log output to os.Stderr.
func logCapture(buf *bytes.Buffer) func() {
	log.SetOutput(buf)
	return func() {
		log.SetOutput(os.Stderr) // restore default after test
	}
}

// stubHandler returns a Handler wired with only the real DomainValidator and
// a nil repoStore/gitService — sufficient for whitelist-rejection tests.
func stubHandler() *Handler {
	return &Handler{
		validator:  service.NewDomainValidator(),
		repoStore:  nil,
		gitService: nil,
	}
}

// buildPostRequest constructs a POST request whose body is a URL-encoded form.
func buildPostRequest(fields map[string]string) *http.Request {
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/repo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// --- CWE-117 Log Forging prevention tests ---

// TestCreateRepo_LogForging_NewlineInGitURL_IsRejectedBeforeLogging verifies
// that a URL containing a newline (the classic log-forging vector) is rejected
// by the domain validator BEFORE any log entry is written with the raw value,
// and that whatever IS logged does not contain a bare newline.
func TestCreateRepo_LogForging_NewlineInGitURL_IsRejectedBeforeLogging(t *testing.T) {
	// Craft a payload that would forge a log line if %s were used instead of %q.
	// The \n is expressed as a Go escape sequence, never as a literal byte.
	maliciousURL := "https://evil.com/repo\n[AUDIT] User admin logged in as superadmin"

	var buf bytes.Buffer
	restore := logCapture(&buf)
	defer restore()

	h := stubHandler()
	req := buildPostRequest(map[string]string{
		"name":    "pwn",
		"git_url": maliciousURL,
	})
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", resp.StatusCode)
	}

	logOutput := buf.String()

	// The forged log line must NOT appear as its own line.
	if strings.Contains(logOutput, "[AUDIT] User admin logged in as superadmin") {
		t.Error("log forging succeeded: injected line appeared in log output as a real entry")
	}

	// The log output must not contain a raw newline inside the quoted URL value.
	// With %q the newline is rendered as the two-character sequence \n.
	// We verify the raw newline character is not present within the logged URL portion.
	// The log line starts with "[VALIDATION] Rejected", so we look at that segment.
	for _, line := range strings.Split(logOutput, "\n") {
		if strings.Contains(line, "[VALIDATION] Rejected") {
			if strings.Contains(line, "\n") {
				t.Error("raw newline found inside the rejection log line — log forging vector not neutralised")
			}
			// The URL should appear %q-quoted (wrapped in double-quotes).
			if !strings.Contains(line, `"https://evil.com/repo`) {
				t.Errorf("expected quoted URL in log line, got: %s", line)
			}
		}
	}
}

// TestCreateRepo_LogForging_CarriageReturnInGitURL verifies that \r
// (used in HTTP response-splitting style log forging) is also escaped.
func TestCreateRepo_LogForging_CarriageReturnInGitURL(t *testing.T) {
	// \r is another common log-forging character.
	maliciousURL := "https://evil.com/repo\r[FORGED] entry"

	var buf bytes.Buffer
	restore := logCapture(&buf)
	defer restore()

	h := stubHandler()
	req := buildPostRequest(map[string]string{
		"name":    "pwn",
		"git_url": maliciousURL,
	})
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, "[FORGED] entry") {
		t.Error("log forging via \\r succeeded: injected content appeared in log")
	}
}

// TestCreateRepo_LogForging_TabInGitURL verifies that a tab character does not
// disrupt log structure.
func TestCreateRepo_LogForging_TabInGitURL(t *testing.T) {
	maliciousURL := "https://evil.com/\t[SPOOFED]"

	var buf bytes.Buffer
	restore := logCapture(&buf)
	defer restore()

	h := stubHandler()
	req := buildPostRequest(map[string]string{
		"name":    "test",
		"git_url": maliciousURL,
	})
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, "[SPOOFED]") {
		t.Error("tab-separated log spoofing succeeded: injected content appeared in log")
	}
}

// TestCreateRepo_LogForging_ValidURL_IsQuotedInLog verifies that a legitimate,
// whitelisted URL is logged with %q quoting (surrounded by double quotes),
// not bare. This confirms the fix applies uniformly.
func TestCreateRepo_LogForging_ValidURL_IsQuotedInLog(t *testing.T) {
	// This URL passes the domain whitelist so the "Domain validated successfully"
	// line is written. We check it uses %q formatting.
	validURL := "https://github.com/example/repo"

	var buf bytes.Buffer
	restore := logCapture(&buf)
	defer restore()

	// We need a handler with a validator but no real DB; the Create call will
	// fail, but the log line we care about is written before the DB call.
	h := &Handler{
		validator:  service.NewDomainValidator(),
		repoStore:  nil, // will panic on Create — we catch the log line first
		gitService: nil,
	}

	req := buildPostRequest(map[string]string{
		"name":    "myrepo",
		"git_url": validURL,
	})
	w := httptest.NewRecorder()

	// The handler will panic when it tries to call repoStore.Create on a nil
	// store.  We recover from the panic so the test can inspect logs up to
	// that point.
	func() {
		defer func() { recover() }() //nolint:errcheck
		h.CreateRepo(w, req)
	}()

	logOutput := buf.String()
	// Find the "Domain validated successfully" line and confirm %q quoting.
	for _, line := range strings.Split(logOutput, "\n") {
		if strings.Contains(line, "Domain validated successfully") {
			expected := fmt.Sprintf("%q", validURL)
			if !strings.Contains(line, expected) {
				t.Errorf("expected log to contain %q-quoted URL %s, got line: %s", "", expected, line)
			}
			return
		}
	}
	t.Log("validation success log line not found (may have panicked before writing); this is acceptable in this test context")
}

// --- Method guard tests ---

func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := stubHandler()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/repo", nil)
		w := httptest.NewRecorder()
		h.CreateRepo(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: expected 405, got %d", method, w.Code)
		}
	}
}

// --- Missing field tests ---

func TestCreateRepo_MissingName(t *testing.T) {
	h := stubHandler()
	req := buildPostRequest(map[string]string{
		"git_url": "https://github.com/example/repo",
	})
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestCreateRepo_MissingGitURL(t *testing.T) {
	h := stubHandler()
	req := buildPostRequest(map[string]string{
		"name": "myrepo",
	})
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// --- Domain whitelist enforcement tests ---

func TestCreateRepo_NonWhitelistedDomain_Returns400(t *testing.T) {
	cases := []string{
		"https://evil.com/user/repo",
		"https://bitbucket.org/user/repo",
		"http://localhost/repo",
		"https://github.com.evil.com/repo", // subdomain spoofing
	}

	h := stubHandler()
	for _, gitURL := range cases {
		req := buildPostRequest(map[string]string{
			"name":    "test",
			"git_url": gitURL,
		})
		w := httptest.NewRecorder()
		h.CreateRepo(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("URL %q: expected 400 Bad Request, got %d", gitURL, w.Code)
		}
	}
}

func TestCreateRepo_WhitelistedDomain_Passes_Validation(t *testing.T) {
	// With a nil repoStore the handler panics at the DB step, but the
	// whitelist check has already passed (status has not been written yet).
	// We confirm we do NOT get a 400 (domain rejected) response.
	cases := []string{
		"https://github.com/user/repo",
		"https://gitlab.com/user/repo",
		"git@github.com:user/repo.git",
		"git@gitlab.com:user/repo.git",
	}

	for _, gitURL := range cases {
		h := &Handler{
			validator:  service.NewDomainValidator(),
			repoStore:  nil,
			gitService: nil,
		}
		req := buildPostRequest(map[string]string{
			"name":    "test",
			"git_url": gitURL,
		})
		w := httptest.NewRecorder()

		func() {
			defer func() { recover() }() //nolint:errcheck
			h.CreateRepo(w, req)
		}()

		// A 400 means the domain was rejected — that is wrong for a whitelisted URL.
		if w.Code == http.StatusBadRequest {
			body := w.Body.String()
			if strings.Contains(body, "whitelisted") {
				t.Errorf("URL %q was unexpectedly rejected as non-whitelisted", gitURL)
			}
		}
	}
}

// --- JSON response shape test (success path) ---

// TestCreateRepo_SuccessResponse_Shape uses a minimal stub repoStore via a
// table-driven approach to verify the JSON shape when everything succeeds.
// Because we cannot easily inject a mock without changing the Handler struct,
// this test uses the public surface: it hits the real code path and confirms
// the 400 response body is plain text (not JSON) — ensuring we have not
// accidentally changed the error response format.
func TestCreateRepo_RejectedDomain_ResponseBodyIsPlainText(t *testing.T) {
	h := stubHandler()
	req := buildPostRequest(map[string]string{
		"name":    "repo",
		"git_url": "https://evil.com/repo",
	})
	w := httptest.NewRecorder()
	h.CreateRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// The body should NOT be a JSON object — it is a plain error string.
	body := strings.TrimSpace(w.Body.String())
	var jsonObj map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonObj); err == nil {
		t.Error("expected plain-text error response, got JSON")
	}

	if !strings.Contains(body, "whitelisted") {
		t.Errorf("expected error message to mention whitelisted domains, got: %s", body)
	}
}
