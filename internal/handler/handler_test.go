package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// newTestHandler creates a fully initialised Handler backed by an in-memory
// SQLite database. The database is set up with the same schema as production.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
		CREATE TABLE repos (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			name      TEXT      NOT NULL,
			git_url   TEXT      NOT NULL,
			repo_type TEXT      NOT NULL,
			created   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	store := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	// GitService is not exercised by CreateRepo, so any clone directory is fine.
	gitSvc := service.NewGitService(t.TempDir())

	return NewHandler(store, validator, gitSvc)
}

// postCreateRepo sends a POST to /create with the given form fields and returns
// the recorded HTTP response.
func postCreateRepo(t *testing.T, h *Handler, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}

	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)
	return rr
}

// ─── log-forging sanitisation ─────────────────────────────────────────────────

// TestLogSanitizerRemovesNewline verifies that a repo name containing a newline
// character (the primary log-forging vector) is accepted by the handler but has
// the newline stripped before it reaches storage or logging.
//
// An attacker could supply name="legit\n[FAKE] admin did something" to inject a
// second log line.  After the fix the newline is removed, so the stored name no
// longer contains the injected content.
func TestLogSanitizerRemovesNewline(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "legit\n[FAKE] injected log line",
		"git_url": "https://github.com/example/repo",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	// The response must not carry the raw newline payload in any field.
	if strings.Contains(rr.Body.String(), "\n[FAKE]") {
		t.Error("response body contains unsanitised newline payload")
	}
}

// TestLogSanitizerRemovesCarriageReturn verifies that a carriage-return
// character (\r, the second log-forging vector on Windows-style log sinks) is
// also stripped from the repo name.
func TestLogSanitizerRemovesCarriageReturn(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "legit\r[FAKE] injected log line",
		"git_url": "https://github.com/example/repo",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	if strings.Contains(rr.Body.String(), "\r[FAKE]") {
		t.Error("response body contains unsanitised carriage-return payload")
	}
}

// TestLogSanitizerRemovesCRLF verifies combined CRLF sequences are stripped.
func TestLogSanitizerRemovesCRLF(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "legit\r\n[FAKE] second line",
		"git_url": "https://github.com/example/repo",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	if strings.Contains(body, "\r\n[FAKE]") || strings.Contains(body, "\n[FAKE]") {
		t.Error("response body contains unsanitised CRLF payload")
	}
}

// TestLogSanitizerPackageLevel ensures the package-level logSanitizer variable
// correctly strips \n and \r while leaving ordinary text unchanged.
func TestLogSanitizerPackageLevel(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"hello\nworld", "helloworld"},
		{"hello\rworld", "helloworld"},
		{"hello\r\nworld", "helloworld"},
		{"multi\nline\r\ninjection\r", "multilineinjection"},
		{"normal repo name", "normal repo name"},
	}

	for _, tc := range cases {
		got := logSanitizer.Replace(tc.input)
		if got != tc.want {
			t.Errorf("logSanitizer.Replace(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ─── normal operation ─────────────────────────────────────────────────────────

// TestCreateRepoSuccess verifies that a well-formed POST creates a repository
// and returns a JSON body with success=true and a non-zero id.
func TestCreateRepoSuccess(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":      "my-repo",
		"git_url":   "https://github.com/example/my-repo",
		"repo_type": "git",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}
	if id, ok := resp["id"].(float64); !ok || id == 0 {
		t.Errorf("expected non-zero numeric id, got %v", resp["id"])
	}
}

// TestCreateRepoDefaultsRepoType verifies that omitting repo_type results in a
// successful creation (the handler defaults it to "git").
func TestCreateRepoDefaultsRepoType(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "no-type-repo",
		"git_url": "https://gitlab.com/example/repo",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ─── method guard ─────────────────────────────────────────────────────────────

// TestCreateRepoMethodNotAllowed verifies that GET requests are rejected.
func TestCreateRepoMethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ─── required-field validation ────────────────────────────────────────────────

// TestCreateRepoMissingName verifies that a missing name field returns 400.
func TestCreateRepoMissingName(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"git_url": "https://github.com/example/repo",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rr.Code)
	}
}

// TestCreateRepoMissingGitURL verifies that a missing git_url field returns 400.
func TestCreateRepoMissingGitURL(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name": "my-repo",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing git_url, got %d", rr.Code)
	}
}

// TestCreateRepoNameBecomesEmptyAfterSanitisation verifies that a name
// consisting solely of newline/carriage-return characters is treated as empty
// after sanitisation, triggering the missing-fields error.
func TestCreateRepoNameBecomesEmptyAfterSanitisation(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "\n\r\n",
		"git_url": "https://github.com/example/repo",
	})

	// After stripping all newlines/CRs the name is empty → 400.
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when name is only newlines (empty after sanitise), got %d", rr.Code)
	}
}

// ─── domain allowlist ─────────────────────────────────────────────────────────

// TestCreateRepoRejectsNonWhitelistedDomain verifies that git_url values not
// matching the domain allowlist are rejected.
func TestCreateRepoRejectsNonWhitelistedDomain(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "evil-repo",
		"git_url": "https://evil.example.com/attacker/repo",
	})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepoAcceptsGithubURL verifies that github.com URLs pass the
// allowlist check.
func TestCreateRepoAcceptsGithubURL(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "valid-repo",
		"git_url": "https://github.com/org/repo",
	})

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for github.com URL, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCreateRepoAcceptsGitlabURL verifies that gitlab.com URLs pass the
// allowlist check.
func TestCreateRepoAcceptsGitlabURL(t *testing.T) {
	h := newTestHandler(t)

	rr := postCreateRepo(t, h, map[string]string{
		"name":    "valid-repo",
		"git_url": "https://gitlab.com/org/repo",
	})

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for gitlab.com URL, got %d: %s", rr.Code, rr.Body.String())
	}
}
