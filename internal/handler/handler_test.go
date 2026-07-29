package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/models"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// --- stub implementations of repoStoreInterface ---

// stubStore is a minimal in-memory stub that satisfies repoStoreInterface
// without requiring a real SQLite database.
type stubStore struct {
	createFn func(name, gitURL, repoType string) (int64, error)
	getByID  func(id int) (*models.Repository, error)
	listFn   func() ([]*models.Repository, error)
}

func (s *stubStore) Create(name, gitURL, repoType string) (int64, error) {
	if s.createFn != nil {
		return s.createFn(name, gitURL, repoType)
	}
	return 1, nil
}

func (s *stubStore) GetByID(id int) (*models.Repository, error) {
	if s.getByID != nil {
		return s.getByID(id)
	}
	return nil, nil
}

func (s *stubStore) List() ([]*models.Repository, error) {
	if s.listFn != nil {
		return s.listFn()
	}
	return nil, nil
}

// --- captureHandler: slog.Handler that records log records for assertions ---

// captureHandler implements slog.Handler and stores every record that is
// handled, allowing tests to assert on structured log fields.
type captureHandler struct {
	records []slog.Record
}

func (c *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (c *captureHandler) Handle(_ context.Context, r slog.Record) error {
	c.records = append(c.records, r)
	return nil
}

func (c *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return c }
func (c *captureHandler) WithGroup(_ string) slog.Handler      { return c }

// installCapture replaces the default slog logger with one backed by a
// captureHandler and returns the handler plus a cleanup function that restores
// the original logger.
func installCapture(t *testing.T) (*captureHandler, func()) {
	t.Helper()
	ch := &captureHandler{}
	orig := slog.Default()
	slog.SetDefault(slog.New(ch))
	return ch, func() { slog.SetDefault(orig) }
}

// newValidHandler returns a Handler wired with a real DomainValidator and the
// provided stub store. gitService is left nil because tests that reach the
// git-clone path are out of scope for this file.
func newValidHandler(store repoStoreInterface) *Handler {
	return &Handler{
		repoStore: store,
		validator: service.NewDomainValidator(),
	}
}

// postForm is a test helper that fires a POST request with form-encoded body
// against the given handler function.
func postForm(h *Handler, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// findRepoCreatedRecord scans the captured records and returns the first one
// whose message is "repo created", or nil if none is found.
func findRepoCreatedRecord(ch *captureHandler) *slog.Record {
	for i := range ch.records {
		if ch.records[i].Message == "repo created" {
			return &ch.records[i]
		}
	}
	return nil
}

// attrValue iterates over a record's attributes and returns the slog.Value for
// the given key, plus a boolean indicating whether the key was found.
func attrValue(r *slog.Record, key string) (slog.Value, bool) {
	var val slog.Value
	var found bool
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val = a.Value
			found = true
			return false
		}
		return true
	})
	return val, found
}

// =============================================================================
// Tests for the Log Forging remediation (CWE-117)
// =============================================================================

// TestCreateRepo_StructuredLog_UserNameIsAttribute verifies that after the fix
// the "name" value from the form is recorded as a typed slog attribute rather
// than being interpolated into the log message string.  An attacker-controlled
// value that contains embedded newlines or percent-format directives must NOT
// appear in the message; it must only appear as the value of the "name" key.
func TestCreateRepo_StructuredLog_UserNameIsAttribute(t *testing.T) {
	maliciousNames := []struct {
		label string
		value string
	}{
		{
			label: "newline_injection",
			// Classic log-forging payload: embedded newline inserts a fake log line.
			value: "legit\n[REPO] Created repo ID=999, name='attacker', url='evil.com'",
		},
		{
			label: "crlf_injection",
			value: "legit\r\n[ATTACKER] injected audit entry",
		},
		{
			label: "percent_verb_injection",
			// Would corrupt printf-style output or cause a crash if fed directly
			// to a Printf format string as a %s argument carrying further verbs.
			value: "%d %s %x %n injected",
		},
		{
			label: "special_characters",
			value: "repo\twith\ttabs and unicode éà",
		},
	}

	for _, tc := range maliciousNames {
		t.Run(tc.label, func(t *testing.T) {
			ch, restore := installCapture(t)
			defer restore()

			h := newValidHandler(&stubStore{
				createFn: func(_, _, _ string) (int64, error) { return 42, nil },
			})

			form := url.Values{}
			form.Set("name", tc.value)
			form.Set("git_url", "https://github.com/test/repo")
			form.Set("repo_type", "git")

			rr := postForm(h, form)
			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
			}

			rec := findRepoCreatedRecord(ch)
			if rec == nil {
				t.Fatal("expected a slog record with message 'repo created' to be emitted")
			}

			// The message string itself must NOT contain the user-supplied value.
			if strings.Contains(rec.Message, tc.value) {
				t.Errorf("log message must NOT embed the user-supplied name; message=%q", rec.Message)
			}

			// The user-supplied value must be present as the typed "name" attribute.
			nameVal, ok := attrValue(rec, "name")
			if !ok {
				t.Fatal("expected slog attribute 'name' to be present in the log record")
			}
			if nameVal.String() != tc.value {
				t.Errorf("slog attribute 'name' = %q, want %q", nameVal.String(), tc.value)
			}
		})
	}
}

// TestCreateRepo_StructuredLog_RecordHasIDAndURL verifies that the structured
// log record includes "id" and "url" attributes in addition to "name".
func TestCreateRepo_StructuredLog_RecordHasIDAndURL(t *testing.T) {
	ch, restore := installCapture(t)
	defer restore()

	const expectedID = int64(99)
	const expectedURL = "https://gitlab.com/group/myrepo"

	h := newValidHandler(&stubStore{
		createFn: func(_, _, _ string) (int64, error) { return expectedID, nil },
	})

	form := url.Values{}
	form.Set("name", "myrepo")
	form.Set("git_url", expectedURL)

	rr := postForm(h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	rec := findRepoCreatedRecord(ch)
	if rec == nil {
		t.Fatal("expected 'repo created' slog record")
	}

	idVal, ok := attrValue(rec, "id")
	if !ok {
		t.Fatal("expected slog attribute 'id' in 'repo created' record")
	}
	if idVal.Int64() != expectedID {
		t.Errorf("slog attribute 'id' = %d, want %d", idVal.Int64(), expectedID)
	}

	urlVal, ok := attrValue(rec, "url")
	if !ok {
		t.Fatal("expected slog attribute 'url' in 'repo created' record")
	}
	if urlVal.String() != expectedURL {
		t.Errorf("slog attribute 'url' = %q, want %q", urlVal.String(), expectedURL)
	}
}

// =============================================================================
// Regression / functional tests
// =============================================================================

// TestCreateRepo_ValidRequest verifies that the handler still returns a proper
// JSON success response after the log-forging fix was applied.
func TestCreateRepo_ValidRequest(t *testing.T) {
	ch, restore := installCapture(t)
	defer restore()

	h := newValidHandler(&stubStore{
		createFn: func(name, gitURL, repoType string) (int64, error) { return 7, nil },
	})

	form := url.Values{}
	form.Set("name", "my-repo")
	form.Set("git_url", "https://github.com/example/my-repo")
	form.Set("repo_type", "git")

	rr := postForm(h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	if int64(resp["id"].(float64)) != 7 {
		t.Errorf("expected id=7, got %v", resp["id"])
	}

	// Also verify a structured log record was emitted (not just the response).
	if rec := findRepoCreatedRecord(ch); rec == nil {
		t.Error("expected 'repo created' slog record to be emitted on success")
	}
}

// TestCreateRepo_MissingFields verifies that requests without required fields
// receive a 400 response and no "repo created" log is emitted.
func TestCreateRepo_MissingFields(t *testing.T) {
	cases := []struct {
		label    string
		formData url.Values
	}{
		{"missing name", url.Values{"git_url": {"https://github.com/test/repo"}}},
		{"missing git_url", url.Values{"name": {"test-repo"}}},
		{"both missing", url.Values{}},
	}

	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			ch, restore := installCapture(t)
			defer restore()

			h := newValidHandler(&stubStore{})

			req := httptest.NewRequest(http.MethodPost, "/api/repo/create",
				strings.NewReader(tc.formData.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			h.CreateRepo(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request, got %d", rr.Code)
			}
			if rec := findRepoCreatedRecord(ch); rec != nil {
				t.Error("unexpected 'repo created' log record emitted for rejected request")
			}
		})
	}
}

// TestCreateRepo_NonWhitelistedDomain ensures that a non-whitelisted git URL
// is rejected before the "repo created" log record is written.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	ch, restore := installCapture(t)
	defer restore()

	h := newValidHandler(&stubStore{
		createFn: func(_, _, _ string) (int64, error) { return 1, nil },
	})

	form := url.Values{}
	form.Set("name", "evil-repo")
	form.Set("git_url", "https://evil.com/attacker/repo")

	rr := postForm(h, form)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for non-whitelisted domain, got %d", rr.Code)
	}

	// No "repo created" record should be emitted when creation is rejected.
	if rec := findRepoCreatedRecord(ch); rec != nil {
		t.Error("unexpected 'repo created' slog record emitted for rejected domain")
	}
}

// TestCreateRepo_MethodNotAllowed verifies that only POST requests are accepted.
func TestCreateRepo_MethodNotAllowed(t *testing.T) {
	h := newValidHandler(&stubStore{})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/repo/create", nil)
		rr := httptest.NewRecorder()
		h.CreateRepo(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405 Method Not Allowed, got %d", method, rr.Code)
		}
	}
}

// TestCreateRepo_DefaultRepoType verifies that repo_type defaults to "git"
// when not supplied in the form.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	var capturedRepoType string
	h := newValidHandler(&stubStore{
		createFn: func(_, _, repoType string) (int64, error) {
			capturedRepoType = repoType
			return 1, nil
		},
	})

	form := url.Values{}
	form.Set("name", "test")
	form.Set("git_url", "https://github.com/test/repo")
	// repo_type intentionally omitted

	rr := postForm(h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if capturedRepoType != "git" {
		t.Errorf("expected default repo_type 'git', got %q", capturedRepoType)
	}
}

// TestCreateRepo_LoggingIsStructured_NotPrintf is a smoke test that verifies
// the standard log package buffer does NOT receive the "repo created" line
// (which used to be written via log.Printf before the fix).  After the fix the
// record must be emitted via slog only.
func TestCreateRepo_LoggingIsStructured_NotPrintf(t *testing.T) {
	// Redirect the legacy log package output to a buffer.
	var legacyBuf bytes.Buffer
	log.SetOutput(&legacyBuf)
	origFlags := log.Flags()
	log.SetFlags(0)
	defer func() {
		log.SetFlags(origFlags)
		log.SetOutput(nil)
	}()

	// Install a slog capture logger (does NOT write to legacyBuf).
	ch, restore := installCapture(t)
	defer restore()

	h := newValidHandler(&stubStore{
		createFn: func(_, _, _ string) (int64, error) { return 1, nil },
	})

	form := url.Values{}
	form.Set("name", "structured-test")
	form.Set("git_url", "https://github.com/test/structured")

	rr := postForm(h, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// The "repo created" record must appear in slog capture...
	if rec := findRepoCreatedRecord(ch); rec == nil {
		t.Error("expected 'repo created' slog record to be emitted")
	}

	// ...and must NOT appear in the legacy log buffer.
	if strings.Contains(legacyBuf.String(), "repo created") {
		t.Errorf("'repo created' must not be written via the legacy log.Printf; legacy log output: %q", legacyBuf.String())
	}
}
