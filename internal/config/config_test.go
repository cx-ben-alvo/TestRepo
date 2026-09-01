package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that Load returns sensible defaults when no
// environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Ensure the relevant vars are unset for a clean environment.
	for _, env := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(env)
	}

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("expected default ServerPort to be non-empty")
	}
	if cfg.CloneDir == "" {
		t.Error("expected default CloneDir to be non-empty")
	}
	if cfg.DownloadDir == "" {
		t.Error("expected default DownloadDir to be non-empty")
	}
}

// TestLoad_TLSDefaults ensures that TLS is NOT enabled by default (no cert/key
// paths are hard-coded into the binary).  The server start-up code treats a
// missing TLS configuration as a fatal error, so this test confirms that the
// operator must supply the values explicitly.
func TestLoad_TLSDefaults(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got %q", cfg.TLSKeyFile)
	}
}

// TestTLSEnabled_BothSet verifies TLSEnabled returns true when both cert and
// key paths are configured.
func TestTLSEnabled_BothSet(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "/etc/ssl/server.crt",
		TLSKeyFile:  "/etc/ssl/server.key",
	}
	if !cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() == true when both cert and key are set")
	}
}

// TestTLSEnabled_OnlyCert verifies TLSEnabled returns false when only the
// certificate is set (key is missing).
func TestTLSEnabled_OnlyCert(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "/etc/ssl/server.crt",
		TLSKeyFile:  "",
	}
	if cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() == false when only cert is set")
	}
}

// TestTLSEnabled_OnlyKey verifies TLSEnabled returns false when only the
// private key is set (cert is missing).
func TestTLSEnabled_OnlyKey(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "",
		TLSKeyFile:  "/etc/ssl/server.key",
	}
	if cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() == false when only key is set")
	}
}

// TestTLSEnabled_NeitherSet verifies TLSEnabled returns false when neither
// cert nor key is configured.  This is the default state and prevents the
// server from accidentally starting without TLS.
func TestTLSEnabled_NeitherSet(t *testing.T) {
	cfg := &Config{}
	if cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() == false when neither cert nor key is set")
	}
}

// TestLoad_TLSFromEnv verifies that TLS paths are loaded from environment
// variables when they are set.
func TestLoad_TLSFromEnv(t *testing.T) {
	const certPath = "/run/secrets/tls.crt"
	const keyPath = "/run/secrets/tls.key"

	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)
	defer os.Unsetenv("TLS_CERT_FILE")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("TLSCertFile: got %q, want %q", cfg.TLSCertFile, certPath)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("TLSKeyFile: got %q, want %q", cfg.TLSKeyFile, keyPath)
	}
	if !cfg.TLSEnabled() {
		t.Error("expected TLSEnabled() == true after setting both env vars")
	}
}

// TestLoad_PortFromEnv verifies the server port is taken from the environment.
func TestLoad_PortFromEnv(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, ":9443")
	}
}
