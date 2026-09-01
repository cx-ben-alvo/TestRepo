package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that Load returns the expected default values when
// no environment variables are set. In particular it checks that the default
// port is the TLS port (:8443) and that TLS cert/key paths default to empty
// strings (forcing the caller to supply them explicitly).
func TestLoad_Defaults(t *testing.T) {
	// Ensure the relevant env vars are absent so defaults kick in.
	for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		t.Setenv(key, "")
	}

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort :8443, got %q", cfg.ServerPort)
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE are read
// from environment variables and exposed on the Config struct.
func TestLoad_TLSEnvVars(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/server.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/server.crt" {
		t.Errorf("expected TLSCertFile /etc/ssl/server.crt, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/server.key" {
		t.Errorf("expected TLSKeyFile /etc/ssl/server.key, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_CustomPort verifies that SERVER_PORT is read from the environment.
func TestLoad_CustomPort(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort :9443, got %q", cfg.ServerPort)
	}
}

// TestLoad_CloneDirEnv verifies CLONE_DIR is read from the environment.
func TestLoad_CloneDirEnv(t *testing.T) {
	t.Setenv("CLONE_DIR", "/tmp/test-clones")

	cfg := Load()

	if cfg.CloneDir != "/tmp/test-clones" {
		t.Errorf("expected CloneDir /tmp/test-clones, got %q", cfg.CloneDir)
	}
}

// TestLoad_DownloadDirEnv verifies DOWNLOAD_DIR is read from the environment.
func TestLoad_DownloadDirEnv(t *testing.T) {
	t.Setenv("DOWNLOAD_DIR", "/tmp/test-downloads")

	cfg := Load()

	if cfg.DownloadDir != "/tmp/test-downloads" {
		t.Errorf("expected DownloadDir /tmp/test-downloads, got %q", cfg.DownloadDir)
	}
}

// TestLoad_AllEnvVars verifies all configuration fields are read together.
func TestLoad_AllEnvVars(t *testing.T) {
	t.Setenv("SERVER_PORT", ":8444")
	t.Setenv("CLONE_DIR", "/tmp/clones")
	t.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	t.Setenv("TLS_CERT_FILE", "/certs/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/certs/tls.key")

	cfg := Load()

	if cfg.ServerPort != ":8444" {
		t.Errorf("ServerPort: expected :8444, got %q", cfg.ServerPort)
	}
	if cfg.CloneDir != "/tmp/clones" {
		t.Errorf("CloneDir: expected /tmp/clones, got %q", cfg.CloneDir)
	}
	if cfg.DownloadDir != "/tmp/downloads" {
		t.Errorf("DownloadDir: expected /tmp/downloads, got %q", cfg.DownloadDir)
	}
	if cfg.TLSCertFile != "/certs/tls.crt" {
		t.Errorf("TLSCertFile: expected /certs/tls.crt, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/certs/tls.key" {
		t.Errorf("TLSKeyFile: expected /certs/tls.key, got %q", cfg.TLSKeyFile)
	}
}

// TestGetEnv_UsesDefault verifies getEnv returns the default when the env var
// is not set.
func TestGetEnv_UsesDefault(t *testing.T) {
	const key = "_TEST_GETENV_MISSING_KEY_"
	os.Unsetenv(key)

	got := getEnv(key, "default-value")
	if got != "default-value" {
		t.Errorf("expected default-value, got %q", got)
	}
}

// TestGetEnv_UsesEnvVar verifies getEnv prefers the environment variable over
// the default.
func TestGetEnv_UsesEnvVar(t *testing.T) {
	const key = "_TEST_GETENV_SET_KEY_"
	t.Setenv(key, "from-env")

	got := getEnv(key, "default-value")
	if got != "from-env" {
		t.Errorf("expected from-env, got %q", got)
	}
}

// TestGetEnv_EmptyVarFallsBackToDefault verifies that an explicitly empty
// environment variable causes getEnv to return the default value (not empty).
// This ensures callers cannot accidentally override a required config field
// with an empty string.
func TestGetEnv_EmptyVarFallsBackToDefault(t *testing.T) {
	const key = "_TEST_GETENV_EMPTY_KEY_"
	t.Setenv(key, "")

	got := getEnv(key, "default-value")
	if got != "default-value" {
		t.Errorf("expected fallback to default-value when env var is empty, got %q", got)
	}
}
