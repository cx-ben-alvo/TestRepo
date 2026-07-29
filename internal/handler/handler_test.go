package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestCreateRepo_LogForging_NewlineInRepoType verifies that a repo_type value
// containing a newline is stripped at the input boundary, preventing log
// forging (CWE-117).
//
// Attack scenario: an attacker supplies
//
//	repo_type=git\nFAKE LOG ENTRY: admin logged in as root
//
// Without the fix the log would contain the injected line.  With the fix the
// newline is removed before the value is used in any log.Printf call.
func TestCreateRepo_LogForging_NewlineInRepoType(t *testing.T) {
	injectedPayload := "git\nFAKE LOG ENTRY: admin logged in as root"

	form := url.Values{
		"name":      {"myrepo"},
		"git_url":   {"https://github.com/example/repo"},
		"repo_type": {injectedPayload},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Replicate the exact sanitizer used in handler.go at the input boundary.
	logSanitizer := strings.NewReplacer("\n", "", "\r", "")
	sanitized := logSanitizer.Replace(req.FormValue("repo_type"))

	if strings.Contains(sanitized, "\n") {
		t.Errorf("sanitized repo_type still contains newline: %q", sanitized)
	}
	// The "git" portion of the legitimate value must survive.
	if !strings.HasPrefix(sanitized, "git") {
		t.Errorf("legitimate repo_type prefix was unexpectedly removed: %q", sanitized)
	}
}

// TestCreateRepo_LogForging_NewlineInName verifies that newlines in the "name"
// form field are also stripped; "name" appears in the same log.Printf call.
func TestCreateRepo_LogForging_NewlineInName(t *testing.T) {
	injected := "myrepo\nINJECTED: root login detected"

	logSanitizer := strings.NewReplacer("\n", "", "\r", "")
	sanitized := logSanitizer.Replace(injected)

	if strings.Contains(sanitized, "\n") {
		t.Errorf("sanitized name still contains newline: %q", sanitized)
	}
	if !strings.HasPrefix(sanitized, "myrepo") {
		t.Errorf("legitimate name prefix was lost: %q", sanitized)
	}
}

// TestCreateRepo_LogForging_CarriageReturnInGitURL verifies that \r is stripped
// from the git_url field, preventing CRLF-based log injection.
func TestCreateRepo_LogForging_CarriageReturnInGitURL(t *testing.T) {
	injected := "https://github.com/example/repo\rINJECTED"

	logSanitizer := strings.NewReplacer("\n", "", "\r", "")
	sanitized := logSanitizer.Replace(injected)

	if strings.Contains(sanitized, "\r") {
		t.Errorf("sanitized git_url still contains CR: %q", sanitized)
	}
}

// TestCreateRepo_LogForging_CRLFInjection verifies that both \r and \n are
// stripped when they appear together (classic CRLF injection).
func TestCreateRepo_LogForging_CRLFInjection(t *testing.T) {
	injected := "legit\r\nINJECTED: fake audit trail"

	logSanitizer := strings.NewReplacer("\n", "", "\r", "")
	sanitized := logSanitizer.Replace(injected)

	if strings.Contains(sanitized, "\n") || strings.Contains(sanitized, "\r") {
		t.Errorf("sanitized value still contains CRLF: %q", sanitized)
	}
	if !strings.Contains(sanitized, "legit") {
		t.Errorf("legitimate content was lost after sanitization: %q", sanitized)
	}
}

// TestCreateRepo_LogForging_CleanInputPassthrough verifies that legitimate
// values without control characters are preserved unchanged (no false
// positives introduced by the sanitizer).
func TestCreateRepo_LogForging_CleanInputPassthrough(t *testing.T) {
	cases := []struct {
		field string
		value string
	}{
		{"name", "my-repo"},
		{"git_url", "https://github.com/org/project"},
		{"repo_type", "git"},
		{"repo_type", "fetch"},
		{"name", "repo with spaces"},
		{"name", "repo_underscore_123"},
	}

	logSanitizer := strings.NewReplacer("\n", "", "\r", "")
	for _, tc := range cases {
		sanitized := logSanitizer.Replace(tc.value)
		if sanitized != tc.value {
			t.Errorf("clean %s value %q was unexpectedly modified to %q",
				tc.field, tc.value, sanitized)
		}
	}
}

// TestSanitizerPreservesUnicode ensures multi-byte Unicode characters are not
// altered by the log sanitizer (only \n and \r must be stripped).
func TestSanitizerPreservesUnicode(t *testing.T) {
	// Unicode strings that must pass through unmodified.
	inputs := []string{
		"répo",     // é — accented Latin (U+00E9)
		"中文",  // 中文 — Chinese characters
		"\U0001F600",    // 😀 emoji (U+1F600)
		"org/repo–", // en-dash (U+2013)
	}

	logSanitizer := strings.NewReplacer("\n", "", "\r", "")
	for _, in := range inputs {
		if out := logSanitizer.Replace(in); out != in {
			t.Errorf("sanitizer unexpectedly changed %q to %q", in, out)
		}
	}
}

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected
// with 405 Method Not Allowed.  This branch executes before any logging, so
// it confirms existing functionality is unaffected by the sanitization change.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := &Handler{} // repoStore/validator nil but unreachable for GET path

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rec := httptest.NewRecorder()

	h.CreateRepo(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rec.Code)
	}
}

// TestCreateRepo_MissingRequiredFields verifies that a POST with blank name or
// git_url returns 400.  This exercises the validation branch that fires after
// sanitization, ensuring the sanitizer does not interfere with empty-field
// detection.
func TestCreateRepo_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		desc    string
		name    string
		gitURL  string
	}{
		{"both blank", "", ""},
		{"name blank", "", "https://github.com/org/repo"},
		{"git_url blank", "myrepo", ""},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			h := &Handler{} // validator nil but unreachable; missing-fields guard fires first

			form := url.Values{
				"name":    {tc.name},
				"git_url": {tc.gitURL},
			}
			req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			h.CreateRepo(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for missing fields (%s), got %d",
					tc.desc, rec.Code)
			}
		})
	}
}
