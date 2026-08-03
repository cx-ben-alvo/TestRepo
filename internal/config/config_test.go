package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultsDoNotSetTLSPaths verifies that when TLS_CERT_FILE and
// TLS_KEY_FILE are absent from the environment, Load returns empty strings for
// both fields.  The server startup code treats empty paths as a fatal
// misconfiguration, so the default must remain empty (not a path that looks
// valid but is missing on disk).
func TestLoad_DefaultsDoNotSetTLSPaths(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile: want empty string by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile: want empty string by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSPathsFromEnvironment verifies that Load correctly reads
// TLS_CERT_FILE and TLS_KEY_FILE from environment variables so that the caller
// can pass real certificate/key paths at runtime without recompilation.
func TestLoad_TLSPathsFromEnvironment(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

	t.Setenv("TLS_CERT_FILE", wantCert)
	t.Setenv("TLS_KEY_FILE", wantKey)

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: want %q, got %q", wantCert, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: want %q, got %q", wantKey, cfg.TLSKeyFile)
	}
}

// TestLoad_DefaultServerPort verifies that the default listening address has
// been updated to :8443 (the conventional HTTPS port) now that the server
// requires TLS.
func TestLoad_DefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	const wantPort = ":8443"
	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: want %q (HTTPS default), got %q", wantPort, cfg.ServerPort)
	}
}

// TestLoad_ServerPortFromEnvironment verifies that SERVER_PORT overrides the
// built-in default.
func TestLoad_ServerPortFromEnvironment(t *testing.T) {
	const wantPort = ":9443"
	t.Setenv("SERVER_PORT", wantPort)

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: want %q, got %q", wantPort, cfg.ServerPort)
	}
}

// TestLoad_AllFieldsReadFromEnvironment verifies that every Config field is
// driven by its corresponding environment variable.
func TestLoad_AllFieldsReadFromEnvironment(t *testing.T) {
	t.Setenv("SERVER_PORT", ":8444")
	t.Setenv("CLONE_DIR", "/tmp/test-clones")
	t.Setenv("DOWNLOAD_DIR", "/tmp/test-downloads")
	t.Setenv("TLS_CERT_FILE", "/tmp/test.crt")
	t.Setenv("TLS_KEY_FILE", "/tmp/test.key")

	cfg := Load()

	if cfg.ServerPort != ":8444" {
		t.Errorf("ServerPort: got %q", cfg.ServerPort)
	}
	if cfg.CloneDir != "/tmp/test-clones" {
		t.Errorf("CloneDir: got %q", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/tmp/test-downloads" {
		t.Errorf("DownloadDir: got %q", cfg.DownloadDir)
	}
	if cfg.TLSCertFile != "/tmp/test.crt" {
		t.Errorf("TLSCertFile: got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/tmp/test.key" {
		t.Errorf("TLSKeyFile: got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSCertFileOnlyDoesNotSetKey verifies that setting only
// TLS_CERT_FILE leaves TLS_KEY_FILE empty, ensuring the server startup
// validation check catches a partially-configured TLS environment.
func TestLoad_TLSCertFileOnlyDoesNotSetKey(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("TLSCertFile: want non-empty, got empty")
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile: want empty when env var is unset, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSKeyFileOnlyDoesNotSetCert mirrors the above for the key-only case.
func TestLoad_TLSKeyFileOnlyDoesNotSetCert(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile: want empty when env var is unset, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile == "" {
		t.Error("TLSKeyFile: want non-empty, got empty")
	}
}
