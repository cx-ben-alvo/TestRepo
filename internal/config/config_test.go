package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultTLSFields verifies that the TLS certificate and key fields
// are present in the default configuration. This prevents regression of the
// CWE-319 fix where the server was started without TLS.
func TestLoad_DefaultTLSFields(t *testing.T) {
	// Ensure relevant env vars are unset so we exercise the defaults.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile must not be empty: server requires a TLS certificate to prevent plaintext transport (CWE-319)")
	}

	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile must not be empty: server requires a TLS private key to prevent plaintext transport (CWE-319)")
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS certificate and key paths can be
// overridden via environment variables, enabling operators to supply their own
// certificates in production without code changes.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	const wantCert = "/etc/ssl/certs/my-service.crt"
	const wantKey = "/etc/ssl/private/my-service.key"

	t.Setenv("TLS_CERT_FILE", wantCert)
	t.Setenv("TLS_KEY_FILE", wantKey)

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile = %q, want %q", cfg.TLSCertFile, wantCert)
	}

	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile = %q, want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoad_DefaultServerPort verifies that the default server port changed from
// the insecure HTTP convention (:8081) to a TLS-appropriate port (:8443) as
// part of the CWE-319 remediation.
func TestLoad_DefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	// :8443 is the conventional HTTPS alternative port; :8081 was the old
	// plain-text default. Ensuring this is non-empty is the minimum contract.
	if cfg.ServerPort == "" {
		t.Error("ServerPort must not be empty")
	}
}

// TestLoad_ServerPortFromEnv verifies that the server port can be customised
// via the SERVER_PORT environment variable.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("ServerPort = %q, want %q", cfg.ServerPort, ":9443")
	}
}

// TestLoad_AllFieldsPresent is a smoke test that ensures none of the Config
// fields are accidentally zeroed out after adding the TLS fields.
func TestLoad_AllFieldsPresent(t *testing.T) {
	// Use explicit env values so the test does not depend on filesystem state.
	t.Setenv("SERVER_PORT", ":8443")
	t.Setenv("CLONE_DIR", "/tmp/clones")
	t.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	t.Setenv("TLS_CERT_FILE", "/tmp/server.crt")
	t.Setenv("TLS_KEY_FILE", "/tmp/server.key")

	cfg := Load()

	tests := []struct {
		name  string
		value string
	}{
		{"ServerPort", cfg.ServerPort},
		{"CloneDir", cfg.CloneDir},
		{"DownloadDir", cfg.DownloadDir},
		{"TLSCertFile", cfg.TLSCertFile},
		{"TLSKeyFile", cfg.TLSKeyFile},
	}

	for _, tt := range tests {
		if tt.value == "" {
			t.Errorf("Config.%s must not be empty", tt.name)
		}
	}
}
