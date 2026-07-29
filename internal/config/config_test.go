package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that Load returns sensible defaults when no
// environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Clear TLS env vars so we get the zero-value defaults.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("expected a non-empty default ServerPort")
	}
	// TLS paths must default to empty strings – the server layer enforces that
	// both must be set before it will start, so defaulting to "" is the safe
	// choice (it prevents an accidental plain-HTTP start).
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty string, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty string, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE are read
// from the environment and stored in the Config struct.
func TestLoad_TLSEnvVars(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

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

// TestLoad_TLSFieldsAbsentWhenEnvUnset confirms that when the TLS env vars are
// absent (not just empty), the fields remain empty strings. This is the
// security-critical case: the server must not silently use a default cert path
// and start serving without the operator explicitly providing certificates.
func TestLoad_TLSFieldsAbsentWhenEnvUnset(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" {
		t.Errorf("expected both TLS paths to be empty when env vars are unset; got cert=%q key=%q",
			cfg.TLSCertFile, cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortOverride verifies SERVER_PORT is respected.
func TestLoad_ServerPortOverride(t *testing.T) {
	const wantPort = ":9443"
	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, wantPort)
	}
}

// TestLoad_PartialTLSConfig checks that setting only one of the two TLS env
// vars leaves the other as an empty string. The server rejects startup when
// either field is empty, so partial config must not be silently accepted.
func TestLoad_PartialTLSConfig(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/some/cert.pem")
	os.Unsetenv("TLS_KEY_FILE")
	defer os.Unsetenv("TLS_CERT_FILE")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("expected TLSCertFile to be set")
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty string when env var is unset, got %q", cfg.TLSKeyFile)
	}
}
