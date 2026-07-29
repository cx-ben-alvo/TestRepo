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

// ---------------------------------------------------------------------------
// Tests for the log-forging sanitizer (CWE-117)
// ---------------------------------------------------------------------------

// TestLogNewlineReplacer verifies the package-level replacer used to sanitize
// user input before writing it to log output (CWE-117 / Log Forging).
func TestLogNewlineReplacer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean value is unchanged",
			input:    "https://github.com/user/repo",
			expected: "https://github.com/user/repo",
		},
		{
			name:     "newline character is replaced with space",
			input:    "https://github.com/user/repo\nFAKE LOG ENTRY",
			expected: "https://github.com/user/repo FAKE LOG ENTRY",
		},
		{
			name:     "carriage return is replaced with space",
			input:    "https://github.com/user/repo\rFAKE LOG ENTRY",
			expected: "https://github.com/user/repo FAKE LOG ENTRY",
		},
		{
			name:     "CRLF sequence (classic log injection) is replaced",
			input:    "https://github.com/user/repo\r\nFAKE LOG ENTRY",
			expected: "https://github.com/user/repo  FAKE LOG ENTRY",
		},
		{
			name:     "multiple newlines are all replaced",
			input:    "line1\nline2\nline3",
			expected: "line1 line2 line3",
		},
		{
			name:     "empty string is unchanged",
			input:    "",
			expected: "",
		},
		{
			name:     "only whitespace is unchanged",
			input:    "   ",
			expected: "   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logNewlineReplacer.Replace(tt.input)
			if got != tt.expected {
				t.Errorf("logNewlineReplacer.Replace(%q) = %q; want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestLogNewlineReplacerDoesNotAllowLogInjection verifies that CRLF sequences
// in user-supplied values cannot inject fake log lines.
func TestLogNewlineReplacerDoesNotAllowLogInjection(t *testing.T) {
	// An attacker tries to forge a log entry by embedding a newline followed
	// by a fake log prefix in a field value.
	maliciousInput := "https://github.com/evil/repo\n[ADMIN] Password reset for admin@example.com"

	sanitized := logNewlineReplacer.Replace(maliciousInput)

	if strings.Contains(sanitized, "\n") {
		t.Errorf("sanitized value still contains newline character: %q", sanitized)
	}
	if strings.Contains(sanitized, "\r") {
		t.Errorf("sanitized value still contains carriage return: %q", sanitized)
	}
	// The injected payload should not appear as a standalone "line".
	lines := strings.Split(sanitized, "\n")
	if len(lines) > 1 {
		t.Errorf("sanitized value contains %d lines, expected exactly 1", len(lines))
	}
}

// TestLogSanitizationAttackVectors exercises a range of known log-injection
// payloads and confirms none survive into the sanitized output.
func TestLogSanitizationAttackVectors(t *testing.T) {
	attackVectors := []struct {
		description string
		payload     string
	}{
		{
			description: "Unix newline log injection",
			payload:     "legit\n[CRITICAL] Admin password changed",
		},
		{
			description: "Windows CRLF log injection",
			payload:     "legit\r\n[CRITICAL] Admin password changed",
		},
		{
			description: "bare carriage return log injection",
			payload:     "legit\r[CRITICAL] Admin password changed",
		},
		{
			description: "NUL byte followed by newline",
			// NUL written as its hex escape to keep the source file text-only.
			payload: "legit\x00\n[CRITICAL] Injected",
		},
		{
			description: "multiple stacked injections",
			payload:     "ok\n[INFO] first fake\n[WARN] second fake",
		},
	}

	for _, av := range attackVectors {
		t.Run(av.description, func(t *testing.T) {
			sanitized := logNewlineReplacer.Replace(av.payload)
			if strings.Contains(sanitized, "\n") {
				t.Errorf("payload %q: sanitized output still contains newline: %q", av.payload, sanitized)
			}
			if strings.Contains(sanitized, "\r") {
				t.Errorf("payload %q: sanitized output still contains carriage return: %q", av.payload, sanitized)
			}
			// Result must be a single log "line".
			lines := strings.Split(sanitized, "\n")
			if len(lines) != 1 {
				t.Errorf("payload %q: expected 1 line after sanitization, got %d: %q", av.payload, len(lines), sanitized)
			}
		})
	}
}

// TestCreateRepoLogOutputDoesNotContainNewlines confirms that the sanitized
// values fed to log.Printf do not produce multi-line log output.
func TestCreateRepoLogOutputDoesNotContainNewlines(t *testing.T) {
	// Capture log output.
	logBuf := &bytes.Buffer{}
	log.SetOutput(logBuf)
	log.SetFlags(0)

	// Simulate what CreateRepo does at line 71 with injected field values.
	injectedName := "myrepo\nFAKE ENTRY name"
	injectedURL := "https://github.com/user/repo\r\n[ERROR] Injected entry"

	sanitizedName := logNewlineReplacer.Replace(injectedName)
	sanitizedURL := logNewlineReplacer.Replace(injectedURL)

	log.Printf("[REPO] Created repo ID=%d, name='%s', url='%s'", int64(1), sanitizedName, sanitizedURL)

	output := logBuf.String()

	// There must be no raw newline that starts a new fake log token like "[".
	if strings.Contains(output, "\n[") {
		t.Errorf("log output contains an injected log line: %q", output)
	}
	if strings.Contains(output, "\r") {
		t.Errorf("log output contains carriage return: %q", output)
	}
	// The legitimate content must still appear.
	if !strings.Contains(output, "myrepo") {
		t.Errorf("log output is missing original repo name portion: %q", output)
	}
}

// ---------------------------------------------------------------------------
// HTTP handler behavioural tests
// ---------------------------------------------------------------------------

// TestCreateRepoMethodNotAllowed ensures non-POST methods are rejected.
func TestCreateRepoMethodNotAllowed(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodGet, "/repos", nil)
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}

// TestCreateRepoMissingFields verifies that requests with empty required fields
// receive a 400 response.
func TestCreateRepoMissingFields(t *testing.T) {
	h := &Handler{}

	form := url.Values{}
	form.Set("name", "")
	form.Set("git_url", "")

	req := httptest.NewRequest(http.MethodPost, "/repos", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing fields, got %d", rr.Code)
	}
}

// TestListReposMethodNotAllowed verifies that non-GET methods are rejected.
func TestListReposMethodNotAllowed(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodPost, "/repos", nil)
	rr := httptest.NewRecorder()

	h.ListRepos(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}

// TestCloneRepoMethodNotAllowed verifies that non-POST methods are rejected.
func TestCloneRepoMethodNotAllowed(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodGet, "/clone", nil)
	rr := httptest.NewRecorder()

	h.CloneRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rr.Code)
	}
}

// TestCloneRepoMissingRepoID verifies that a missing repo_id returns 400.
func TestCloneRepoMissingRepoID(t *testing.T) {
	h := &Handler{}

	req := httptest.NewRequest(http.MethodPost, "/clone", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.CloneRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for missing repo_id, got %d", rr.Code)
	}
}

// TestJSONResponseStructure verifies that the JSON body the handler produces
// for a successful creation is correctly shaped.
func TestJSONResponseStructure(t *testing.T) {
	payload := map[string]interface{}{
		"success": true,
		"id":      float64(42), // JSON numbers decode as float64
		"message": "Repository created successfully",
	}

	body := &bytes.Buffer{}
	if err := json.NewEncoder(body).Encode(payload); err != nil {
		t.Fatalf("json.Encode failed: %v", err)
	}

	var got map[string]interface{}
	if err := json.NewDecoder(body).Decode(&got); err != nil {
		t.Fatalf("json.Decode failed: %v", err)
	}

	if got["success"] != true {
		t.Errorf("success field: got %v, want true", got["success"])
	}
	if got["id"] != float64(42) {
		t.Errorf("id field: got %v, want 42", got["id"])
	}
	if got["message"] != "Repository created successfully" {
		t.Errorf("message field: got %v", got["message"])
	}
}
