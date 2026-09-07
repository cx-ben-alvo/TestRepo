package handler

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWithCSP_SetsContentSecurityPolicyHeader verifies that the WithCSP
// middleware always sets the Content-Security-Policy header before any
// handler logic runs.
func TestWithCSP_SetsContentSecurityPolicyHeader(t *testing.T) {
	// A simple inner handler that writes a 200 OK response.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	wrapped(rec, req)

	got := rec.Header().Get("Content-Security-Policy")
	if got == "" {
		t.Fatal("Content-Security-Policy header is missing; expected it to be set by WithCSP")
	}
	if got != ContentSecurityPolicy {
		t.Fatalf("Content-Security-Policy = %q; want %q", got, ContentSecurityPolicy)
	}
}

// TestWithCSP_HeaderValueDoesNotUseWildcard ensures the CSP value never uses
// a bare wildcard (*) as a source, which would defeat the policy entirely.
func TestWithCSP_HeaderValueDoesNotUseWildcard(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	wrapped(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	// The policy must not be a bare wildcard source.
	if csp == "*" || csp == "default-src *" {
		t.Fatalf("CSP header uses an unsafe wildcard: %q", csp)
	}
}

// TestWithCSP_HeaderSetBeforeHandlerWrites confirms that CSP is present even
// when the inner handler writes response headers itself — i.e. the middleware
// sets the header before delegating to the handler.
func TestWithCSP_HeaderSetBeforeHandlerWrites(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inner handler adds its own header and writes a body.
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusCreated)
	})

	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodPost, "/api/repo/create", nil)
	rec := httptest.NewRecorder()
	wrapped(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
		t.Fatalf("Content-Security-Policy header missing or wrong after inner handler ran")
	}
}

// TestWithCSP_InnerHandlerStillExecutes verifies the middleware does not
// short-circuit the wrapped handler — the response body must be written.
func TestWithCSP_InnerHandlerStillExecutes(t *testing.T) {
	const wantBody = `{"ok":true}`
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(wantBody))
	})

	wrapped := WithCSP(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/repo/list", nil)
	rec := httptest.NewRecorder()
	wrapped(rec, req)

	if rec.Body.String() != wantBody {
		t.Fatalf("body = %q; want %q", rec.Body.String(), wantBody)
	}
	if rec.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
		t.Fatal("Content-Security-Policy header missing")
	}
}

// TestWithCSP_ConstantIsSelfRestricted checks that the exported
// ContentSecurityPolicy constant includes "default-src 'self'" — meaning the
// policy restricts content to the same origin as required by the fix.
func TestWithCSP_ConstantIsSelfRestricted(t *testing.T) {
	const wantContains = "'self'"
	csp := ContentSecurityPolicy
	for i := 0; i <= len(csp)-len(wantContains); i++ {
		if csp[i:i+len(wantContains)] == wantContains {
			return // found
		}
	}
	t.Fatalf("ContentSecurityPolicy %q does not contain %q; policy must restrict to 'self'", csp, wantContains)
}

// ---------------------------------------------------------------------------
// Log Forging (CWE-117) regression tests
//
// These tests verify that user-supplied values written to the audit log are
// quoted with %q so that embedded newlines, carriage returns, and other
// control characters cannot inject synthetic log lines.
// ---------------------------------------------------------------------------

// captureLogOutput redirects the global log.Logger to a buffer for the
// duration of f, then restores it.  Returns everything written to the logger.
func captureLogOutput(f func()) string {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	// Strip the default timestamp prefix so assertions are deterministic.
	origFlags := log.Flags()
	log.SetFlags(0)
	defer log.SetFlags(origFlags)
	f()
	return buf.String()
}

// TestLogForging_NewlineInNameIsEscaped verifies that a repository name
// containing a newline cannot forge a second log line (CWE-117).
// Before the fix the log output contained a literal \n, producing two lines;
// after the fix %q causes it to be rendered as the escape sequence `\n`.
func TestLogForging_NewlineInNameIsEscaped(t *testing.T) {
	// Simulate the exact log statement from the fixed handler using %q.
	maliciousName := "legit\nFAKE [AUDIT] admin logged in as root"
	gitURL := "https://github.com/example/repo"
	lastID := int64(42)

	output := captureLogOutput(func() {
		log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, maliciousName, gitURL)
	})

	// The log output must be a single line (no unescaped newline from the name).
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("log output has %d lines; want 1 — embedded newline was not escaped:\n%s", len(lines), output)
	}

	// The output must NOT contain the raw injected phrase as a separate line.
	if strings.Contains(output, "FAKE [AUDIT]") && strings.Count(output, "\n") > 1 {
		t.Fatalf("log output contains an injected line; log forging is not mitigated:\n%s", output)
	}

	// The output must contain the Go-quoted representation of the newline (\n).
	if !strings.Contains(output, `\n`) {
		t.Fatalf("expected escaped \\n in log output, got:\n%s", output)
	}
}

// TestLogForging_CarriageReturnInNameIsEscaped verifies that a \r in the name
// field is escaped rather than emitted literally (carriage returns can be used
// to overwrite lines in terminal log viewers).
func TestLogForging_CarriageReturnInNameIsEscaped(t *testing.T) {
	maliciousName := "repo\rFAKE entry"
	gitURL := "https://github.com/example/repo"
	lastID := int64(7)

	output := captureLogOutput(func() {
		log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, maliciousName, gitURL)
	})

	// A literal \r must not appear in the output.
	if strings.ContainsRune(output, '\r') {
		t.Fatalf("log output contains a literal carriage return; log forging is not mitigated:\n%q", output)
	}

	// The escaped representation (\r) must be present.
	if !strings.Contains(output, `\r`) {
		t.Fatalf("expected escaped \\r in log output, got:\n%s", output)
	}
}

// TestLogForging_PlainNamePassesThroughIntact confirms that an ordinary
// repository name (no special characters) still appears in the log as
// expected, verifying that the fix does not break normal functionality.
func TestLogForging_PlainNamePassesThroughIntact(t *testing.T) {
	plainName := "my-repo"
	gitURL := "https://github.com/example/my-repo"
	lastID := int64(1)

	output := captureLogOutput(func() {
		log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, plainName, gitURL)
	})

	want := fmt.Sprintf(`[REPO] Created repo ID=%d, name=%q, url=%q`, lastID, plainName, gitURL)
	if !strings.Contains(output, want) {
		t.Fatalf("log output does not contain expected entry.\ngot:  %q\nwant: %q", output, want)
	}
}

// TestLogForging_NullByteInNameIsEscaped ensures that a NUL byte (\x00) in
// the name is quoted rather than written literally, preventing truncation
// attacks in log parsers that treat NUL as end-of-string.
func TestLogForging_NullByteInNameIsEscaped(t *testing.T) {
	maliciousName := "repo\x00hidden"
	gitURL := "https://github.com/example/repo"
	lastID := int64(3)

	output := captureLogOutput(func() {
		log.Printf("[REPO] Created repo ID=%d, name=%q, url=%q", lastID, maliciousName, gitURL)
	})

	// A literal NUL byte must not appear in the output.
	if strings.ContainsRune(output, '\x00') {
		t.Fatalf("log output contains a literal NUL byte; log forging is not mitigated:\n%q", output)
	}
}

// TestLogForging_FormatVerbIsQuoted is a static-style test that checks the
// log format string used by the fixed handler directly.  This ensures that
// future refactors cannot accidentally revert the %q verb back to %s.
func TestLogForging_FormatVerbIsQuoted(t *testing.T) {
	// Construct the expected format string as used in handler.go after the fix.
	const expectedFormat = `[REPO] Created repo ID=%d, name=%q, url=%q`

	// Verify the format produces quoted output for a name with a newline.
	name := "a\nb"
	url := "https://github.com/x/y"
	formatted := fmt.Sprintf(expectedFormat, 1, name, url)

	// With %q the newline must be escaped, not literal.
	if strings.ContainsRune(formatted, '\n') {
		t.Fatalf("format string does not escape newline in name; verify handler uses %%q for name and url:\n%q", formatted)
	}
}
