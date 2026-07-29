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

	"github.com/checkmarx/correlation-demo/internal/models"
	"github.com/checkmarx/correlation-demo/internal/service"
)

// ---- test doubles ----

// fakeRepoStore is an in-memory implementation of the repoStore interface.
type fakeRepoStore struct {
	nextID    int64
	createErr error
	repos     map[int]*models.Repository
}

func newFakeRepoStore(nextID int64) *fakeRepoStore {
	return &fakeRepoStore{
		nextID: nextID,
		repos:  make(map[int]*models.Repository),
	}
}

func (f *fakeRepoStore) Create(name, gitURL, repoType string) (int64, error) {
	if f.createErr != nil {
		return 0, f.createErr
	}
	id := int(f.nextID)
	f.repos[id] = &models.Repository{ID: id, Name: name, GitURL: gitURL, RepoType: repoType}
	return f.nextID, nil
}

func (f *fakeRepoStore) GetByID(id int) (*models.Repository, error) {
	repo, ok := f.repos[id]
	if !ok {
		return nil, nil
	}
	return repo, nil
}

func (f *fakeRepoStore) List() ([]*models.Repository, error) {
	result := make([]*models.Repository, 0, len(f.repos))
	for _, r := range f.repos {
		result = append(result, r)
	}
	return result, nil
}

// fakeDomainValidator is a controllable implementation of the domainValidator interface.
type fakeDomainValidator struct {
	whitelisted bool
}

func (v *fakeDomainValidator) IsWhitelisted(_ string) bool { return v.whitelisted }

// fakeGitCloner is a no-op implementation of the gitCloner interface.
type fakeGitCloner struct{}

func (g *fakeGitCloner) Clone(_ int, _ string) (*service.CloneResult, error) {
	return &service.CloneResult{TargetDir: "/tmp/test", HeadHash: "abc12345", Files: []string{}}, nil
}

// ---- helpers ----

// buildPostRequest constructs an application/x-www-form-urlencoded POST request.
func buildPostRequest(fields map[string]string) *http.Request {
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// captureLogOutput redirects the global logger to a buffer for the test duration.
func captureLogOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0) // remove timestamps to make assertions simpler
	t.Cleanup(func() {
		// Restore logger to default stderr and default flags.
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	})
	return &buf
}

// newHandler constructs a Handler wired with the provided test doubles.
func newHandler(store repoStore, validator domainValidator, cloner gitCloner) *Handler {
	return &Handler{
		repoStore:  store,
		validator:  validator,
		gitService: cloner,
	}
}

// ---- Log Forging (CWE-117) remediation tests ----

// TestCreateRepo_LogForging_NewlineStripped verifies that a newline embedded in the
// git_url form value is stripped before the value is written to the log.
//
// Attack scenario: an attacker submits
//
//	git_url=https://github.com/user/repo\n[FAKE] Admin authenticated successfully
//
// Without the fix the log would contain a second, forged line. After the fix the
// newline and everything after it must not appear.
func TestCreateRepo_LogForging_NewlineStripped(t *testing.T) {
	buf := captureLogOutput(t)

	h := newHandler(
		newFakeRepoStore(1),
		&fakeDomainValidator{whitelisted: true},
		&fakeGitCloner{},
	)

	maliciousURL := "https://github.com/user/repo\n[FAKE] Admin authenticated successfully"
	req := buildPostRequest(map[string]string{
		"name":    "test-repo",
		"git_url": maliciousURL,
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	logged := buf.String()

	// The injected fake log line must not appear.
	if strings.Contains(logged, "[FAKE]") {
		t.Errorf("log forging via LF: injected fake entry appeared in log output:\n%q", logged)
	}

	// A raw newline character must not appear within the logged URL segment.
	if strings.Contains(logged, "\n[FAKE]") {
		t.Errorf("log forging via LF: raw newline still present in log output:\n%q", logged)
	}
}

// TestCreateRepo_LogForging_CarriageReturnStripped verifies that a carriage-return
// character in git_url is stripped before logging to prevent log forging via CR.
func TestCreateRepo_LogForging_CarriageReturnStripped(t *testing.T) {
	buf := captureLogOutput(t)

	h := newHandler(
		newFakeRepoStore(2),
		&fakeDomainValidator{whitelisted: true},
		&fakeGitCloner{},
	)

	maliciousURL := "https://github.com/user/repo\r[FAKE] Security event injected"
	req := buildPostRequest(map[string]string{
		"name":    "test-repo",
		"git_url": maliciousURL,
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	logged := buf.String()

	if strings.Contains(logged, "[FAKE]") {
		t.Errorf("log forging via CR: injected text appeared in log output:\n%q", logged)
	}
}

// TestCreateRepo_LogForging_CRLFStripped verifies that a CRLF sequence in git_url
// is fully stripped before logging.
func TestCreateRepo_LogForging_CRLFStripped(t *testing.T) {
	buf := captureLogOutput(t)

	h := newHandler(
		newFakeRepoStore(3),
		&fakeDomainValidator{whitelisted: true},
		&fakeGitCloner{},
	)

	// Use escape sequences — never raw control bytes in source files.
	maliciousURL := "https://github.com/user/repo\r\n[FAKE] CRLF injected log entry"
	req := buildPostRequest(map[string]string{
		"name":    "test-repo",
		"git_url": maliciousURL,
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	logged := buf.String()

	if strings.Contains(logged, "[FAKE]") {
		t.Errorf("log forging via CRLF: injected text appeared in log output:\n%q", logged)
	}
}

// TestCreateRepo_LogForging_MultipleNewlinesStripped verifies that multiple embedded
// newlines are all removed, preventing a multi-line forged block.
func TestCreateRepo_LogForging_MultipleNewlinesStripped(t *testing.T) {
	buf := captureLogOutput(t)

	h := newHandler(
		newFakeRepoStore(4),
		&fakeDomainValidator{whitelisted: true},
		&fakeGitCloner{},
	)

	maliciousURL := "https://github.com/user/repo\n[LINE1]\n[LINE2]\n[LINE3]"
	req := buildPostRequest(map[string]string{
		"name":    "test-repo",
		"git_url": maliciousURL,
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	logged := buf.String()

	for _, injected := range []string{"[LINE1]", "[LINE2]", "[LINE3]"} {
		if strings.Contains(logged, injected) {
			t.Errorf("log forging: injected marker %q appeared in log output:\n%q", injected, logged)
		}
	}
}

// TestCreateRepo_LogForging_LegitimateURLPreserved verifies that a clean URL is
// still written to the log after the fix (no legitimate data loss).
func TestCreateRepo_LogForging_LegitimateURLPreserved(t *testing.T) {
	buf := captureLogOutput(t)

	h := newHandler(
		newFakeRepoStore(5),
		&fakeDomainValidator{whitelisted: true},
		&fakeGitCloner{},
	)

	legitimateURL := "https://github.com/user/my-repo"
	req := buildPostRequest(map[string]string{
		"name":    "my-repo",
		"git_url": legitimateURL,
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	logged := buf.String()

	if !strings.Contains(logged, "[VALIDATION] Domain validated successfully") {
		t.Errorf("expected validation success log line, got:\n%q", logged)
	}

	if !strings.Contains(logged, legitimateURL) {
		t.Errorf("expected legitimate URL %q in log output, got:\n%q", legitimateURL, logged)
	}
}

// ---- Functional regression tests ----

// TestCreateRepo_Success verifies the happy-path: correct HTTP 200 and JSON response.
func TestCreateRepo_Success(t *testing.T) {
	captureLogOutput(t)

	h := newHandler(
		newFakeRepoStore(10),
		&fakeDomainValidator{whitelisted: true},
		&fakeGitCloner{},
	)

	req := buildPostRequest(map[string]string{
		"name":    "my-repo",
		"git_url": "https://github.com/user/my-repo",
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode JSON response: %v", err)
	}

	if success, ok := resp["success"].(bool); !ok || !success {
		t.Errorf("expected success=true in response, got: %v", resp)
	}

	if _, ok := resp["id"]; !ok {
		t.Errorf("expected 'id' field in response, got: %v", resp)
	}
}

// TestCreateRepo_MissingName verifies that omitting 'name' returns HTTP 400.
func TestCreateRepo_MissingName(t *testing.T) {
	captureLogOutput(t)

	h := newHandler(newFakeRepoStore(1), &fakeDomainValidator{whitelisted: true}, &fakeGitCloner{})

	req := buildPostRequest(map[string]string{
		// name intentionally absent
		"git_url": "https://github.com/user/repo",
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rr.Code)
	}
}

// TestCreateRepo_MissingGitURL verifies that omitting 'git_url' returns HTTP 400.
func TestCreateRepo_MissingGitURL(t *testing.T) {
	captureLogOutput(t)

	h := newHandler(newFakeRepoStore(1), &fakeDomainValidator{whitelisted: true}, &fakeGitCloner{})

	req := buildPostRequest(map[string]string{
		"name": "test-repo",
		// git_url intentionally absent
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing git_url, got %d", rr.Code)
	}
}

// TestCreateRepo_NonWhitelistedDomain verifies that a non-whitelisted domain yields HTTP 400.
func TestCreateRepo_NonWhitelistedDomain(t *testing.T) {
	captureLogOutput(t)

	h := newHandler(newFakeRepoStore(1), &fakeDomainValidator{whitelisted: false}, &fakeGitCloner{})

	req := buildPostRequest(map[string]string{
		"name":    "bad-repo",
		"git_url": "https://evil.example.com/user/repo",
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-whitelisted domain, got %d", rr.Code)
	}
}

// TestCreateRepo_WrongMethod verifies that non-POST methods return HTTP 405.
func TestCreateRepo_WrongMethod(t *testing.T) {
	captureLogOutput(t)

	h := newHandler(newFakeRepoStore(1), &fakeDomainValidator{whitelisted: true}, &fakeGitCloner{})

	req := httptest.NewRequest(http.MethodGet, "/api/repo/create", nil)
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestCreateRepo_DefaultRepoType verifies that repo_type defaults to "git" when absent.
func TestCreateRepo_DefaultRepoType(t *testing.T) {
	captureLogOutput(t)

	store := newFakeRepoStore(1)
	h := newHandler(store, &fakeDomainValidator{whitelisted: true}, &fakeGitCloner{})

	req := buildPostRequest(map[string]string{
		"name":    "my-repo",
		"git_url": "https://github.com/user/my-repo",
		// repo_type intentionally absent
	})
	rr := httptest.NewRecorder()
	h.CreateRepo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	repo, err := store.GetByID(1)
	if err != nil || repo == nil {
		t.Fatalf("expected stored repo, got err=%v repo=%v", err, repo)
	}
	if repo.RepoType != "git" {
		t.Errorf("expected default repo_type='git', got %q", repo.RepoType)
	}
}
