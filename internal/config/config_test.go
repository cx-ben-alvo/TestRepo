package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that Load returns non-empty defaults for
// required configuration fields.
func TestLoad_DefaultValues(t *testing.T) {
	// Clear any env overrides so we test the hard-coded defaults.
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("expected default ServerPort to be non-empty")
	}
	// TLS fields default to empty string; callers are expected to populate them
	// via environment variables. The test just confirms the fields exist and are
	// accessible (compilation would fail otherwise).
	_ = cfg.TLSCertFile
	_ = cfg.TLSKeyFile
}

// TestLoad_TLSEnvVars verifies that TLS certificate and key paths are read
// from the environment variables TLS_CERT_FILE and TLS_KEY_FILE.
func TestLoad_TLSEnvVars(t *testing.T) {
	wantCert := "/etc/ssl/certs/server.crt"
	wantKey := "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: got %q, want %q", cfg.TLSCertFile, wantCert)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: got %q, want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoad_ServerPortEnvVar verifies that the server port can be overridden
// via the SERVER_PORT environment variable.
func TestLoad_ServerPortEnvVar(t *testing.T) {
	want := ":9443"

	os.Setenv("SERVER_PORT", want)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != want {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, want)
	}
}

// TestTLSFieldsPresent is a compile-time guard: if TLSCertFile or TLSKeyFile
// are removed from Config, this test fails to compile, catching regressions
// that would re-expose CWE-319.
func TestTLSFieldsPresent(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "cert.pem",
		TLSKeyFile:  "key.pem",
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		t.Error("TLSCertFile and TLSKeyFile must be present on Config")
	}
}
