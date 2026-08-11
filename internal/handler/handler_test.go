package handler

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/service"
)

// ---- helpers ----------------------------------------------------------------

// captureLog redirects the global logger to a buffer for the duration of fn,
// then returns everything that was written. The global log output is restored
// before captureLog returns.
func captureLog(fn func()) string {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return buf.String()
}

// formRequest builds a POST request with URL-encoded form body.
func formRequest(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// ---- log-forging regression tests ------------------------------------------

// TestCreateRepo_LogDoesNotContainRawNewlineFromGitURL verifies that when a
// user-controlled git_url value contains an embedded newline (a classic
// log-forging payload), the newline does NOT appear unescaped in the log
// output. The fix uses the %q verb which encodes \n as the two-character
// sequence backslash-n rather than an actual line break.
func TestCreateRepo_LogDoesNotContainRawNewlineFromGitURL(t *testing.T) {
	// Craft a git_url that passes the domain whitelist but embeds a log-injection
	// payload: a newline followed by a fake audit entry.
	const injectionPayload = "https://github.com/user/repo\n[FAKE] Injected audit entry"

	req := formRequest(t, map[string]string{
		"name":    "test-repo",
		"git_url": injectionPayload,
	})
	rr := httptest.NewRecorder()

	// We build a Handler with a nil repoStore intentionally. The CreateRepo
	// handler logs the validated URL *before* calling repoStore.Create, so we
	// can observe the log output even though the subsequent DB call will panic.
	// The recover() below catches that panic so the test does not crash.
	h := &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}

	logOutput := captureLog(func() {
		// Recover from the nil-pointer panic that occurs when repoStore.Create
		// is invoked; we only need to observe what was logged before that point.
		func() {
			defer func() { recover() }() //nolint:errcheck
			h.CreateRepo(rr, req)
		}()
	})

	// The raw newline character must NOT appear in the log output unescaped.
	if strings.Contains(logOutput, "\n[FAKE]") {
		t.Errorf("log output contains raw newline injection payload;\n"+
			"this indicates log forging is possible.\nlog output: %q", logOutput)
	}

	// The %q verb should have encoded the newline as the two-character sequence \n.
	if !strings.Contains(logOutput, `\n`) {
		t.Errorf("expected log output to contain escaped newline (\\n) but it did not;\n"+
			"log output: %q", logOutput)
	}
}

// TestCreateRepo_LogDoesNotContainRawCarriageReturnFromGitURL verifies that a
// carriage-return injection (\r) in the git_url is also escaped in the log.
func TestCreateRepo_LogDoesNotContainRawCarriageReturnFromGitURL(t *testing.T) {
	const injectionPayload = "https://github.com/user/repo\r[FAKE] CR-injected entry"

	req := formRequest(t, map[string]string{
		"name":    "test-repo",
		"git_url": injectionPayload,
	})
	rr := httptest.NewRecorder()

	h := &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}

	logOutput := captureLog(func() {
		func() {
			defer func() { recover() }() //nolint:errcheck
			h.CreateRepo(rr, req)
		}()
	})

	if strings.Contains(logOutput, "\r[FAKE]") {
		t.Errorf("log output contains raw carriage-return injection payload;\n"+
			"log output: %q", logOutput)
	}
}

// TestCreateRepo_RejectedURL_LogDoesNotContainRawNewline verifies that the
// rejection log path (the log.Printf call when the domain is not whitelisted)
// is also protected: when a non-whitelisted URL carries an injection payload,
// the log must not contain a raw newline.
func TestCreateRepo_RejectedURL_LogDoesNotContainRawNewline(t *testing.T) {
	// evil.com is not whitelisted; append an injection payload.
	const injectionPayload = "https://evil.com/repo\n[FAKE] Bypass log entry"

	req := formRequest(t, map[string]string{
		"name":    "test-repo",
		"git_url": injectionPayload,
	})
	rr := httptest.NewRecorder()

	h := &Handler{
		repoStore:  nil,
		validator:  service.NewDomainValidator(),
		gitService: nil,
	}

	logOutput := captureLog(func() {
		h.CreateRepo(rr, req)
	})

	// HTTP response must be 400.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 for non-whitelisted domain, got %d", rr.Code)
	}

	// Log must not contain a raw newline at the injection point.
	if strings.Contains(logOutput, "\n[FAKE]") {
		t.Errorf("rejection log contains raw newline injection payload;\n"+
			"log output: %q", logOutput)
	}
}

// ---- functional / positive-path tests --------------------------------------

// TestCreateRepo_MethodNotAllowed verifies that non-POST requests are rejected.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	h := &Handler{validator: service.NewDomainValidator()}
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingFields verifies that requests without name or git_url
// are rejected with HTTP 400.
func TestCreateRepo_MissingFields(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
	}{
		{
			name:   "missing name",
			fields: map[string]string{"git_url": "https://github.com/user/repo"},
		},
		{
			name:   "missing git_url",
			fields: map[string]string{"name": "repo"},
		},
		{
			name:   "both missing",
			fields: map[string]string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := formRequest(t, tc.fields)
			rr := httptest.NewRecorder()

			h := &Handler{validator: service.NewDomainValidator()}
			h.CreateRepo(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s: expected 400, got %d", tc.name, rr.Code)
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that git_urls for disallowed
// domains return HTTP 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	req := formRequest(t, map[string]string{
		"name":    "repo",
		"git_url": "https://evil.com/user/repo",
	})
	rr := httptest.NewRecorder()

	h := &Handler{validator: service.NewDomainValidator()}
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestListRepos_MethodNotAllowed verifies that non-GET requests to ListRepos
// are rejected with HTTP 405.
func TestListRepos_MethodNotAllowed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/repos", nil)
	rr := httptest.NewRecorder()

	h := &Handler{}
	h.ListRepos(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCloneRepo_MethodNotAllowed verifies that non-POST requests to CloneRepo
// are rejected with HTTP 405.
func TestCloneRepo_MethodNotAllowed(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/clone", nil)
	rr := httptest.NewRecorder()

	h := &Handler{}
	h.CloneRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCloneRepo_MissingRepoID verifies that a POST without repo_id is rejected
// with HTTP 400.
func TestCloneRepo_MissingRepoID(t *testing.T) {
	req := formRequest(t, map[string]string{})
	rr := httptest.NewRecorder()

	h := &Handler{}
	h.CloneRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing repo_id, got %d", rr.Code)
	}
}

// ---- log-format safety unit tests ------------------------------------------

// TestLogFormatQuotedVerb_EscapesSpecialCharacters verifies that Go's %q verb
// (used in the fixed log statements) correctly escapes characters that could be
// used for log forging when compared to the unsafe %s verb.
// This test serves as a regression guard for the formatting change.
func TestLogFormatQuotedVerb_EscapesSpecialCharacters(t *testing.T) {
	injectionCases := []struct {
		description string
		input       string
		forbidden   string // must NOT appear literally in %q output
	}{
		{
			description: "newline injection",
			input:       "https://github.com/x\nINJECTED",
			forbidden:   "\nINJECTED",
		},
		{
			description: "carriage return injection",
			input:       "https://github.com/x\rINJECTED",
			forbidden:   "\rINJECTED",
		},
		{
			description: "tab injection",
			input:       "https://github.com/x\tINJECTED",
			forbidden:   "\tINJECTED",
		},
	}

	for _, tc := range injectionCases {
		t.Run(tc.description, func(t *testing.T) {
			formatted := fmt.Sprintf("%q", tc.input)
			if strings.Contains(formatted, tc.forbidden) {
				t.Errorf("%%q format did not escape injection payload;\n"+
					"input: %q\nformatted: %s\nforbidden sequence present: %q",
					tc.input, formatted, tc.forbidden)
			}
		})
	}
}
