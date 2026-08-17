package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that Load() returns the expected default values
// when no environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Clear TLS-related env vars to test defaults
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected default TLSCertFile to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected default TLSKeyFile to be empty, got %q", cfg.TLSKeyFile)
	}
	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort to be %q, got %q", ":8081", cfg.ServerPort)
	}
}

// TestLoad_TLSFromEnv verifies that TLS certificate and key paths are read
// correctly from the TLS_CERT_FILE and TLS_KEY_FILE environment variables.
func TestLoad_TLSFromEnv(t *testing.T) {
	certPath := "/etc/ssl/certs/server.crt"
	keyPath := "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", certPath)
	os.Setenv("TLS_KEY_FILE", keyPath)
	defer os.Unsetenv("TLS_CERT_FILE")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_TLSCertMissingKeyPresent verifies that when only TLS_KEY_FILE is
// set, TLSCertFile remains empty — signalling that the server must refuse to
// start in plain-text mode.
func TestLoad_TLSCertMissingKeyPresent(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty when env var is unset, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile == "" {
		t.Error("expected TLSKeyFile to be non-empty")
	}
}

// TestLoad_TLSKeyMissingCertPresent verifies that when only TLS_CERT_FILE is
// set, TLSKeyFile remains empty — signalling that the server must refuse to
// start in plain-text mode.
func TestLoad_TLSKeyMissingCertPresent(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Unsetenv("TLS_KEY_FILE")
	defer os.Unsetenv("TLS_CERT_FILE")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("expected TLSCertFile to be non-empty")
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty when env var is unset, got %q", cfg.TLSKeyFile)
	}
}

// TestTLSEnforcement_BothFieldsRequired validates the invariant that the
// server startup code depends on: both TLSCertFile AND TLSKeyFile must be
// non-empty for the server to proceed with TLS.  This mirrors the guard added
// in cmd/server/main.go.
func TestTLSEnforcement_BothFieldsRequired(t *testing.T) {
	tests := []struct {
		name        string
		certFile    string
		keyFile     string
		tlsReady    bool // whether the server should be allowed to start
	}{
		{
			name:     "both paths set – TLS ready",
			certFile: "/etc/ssl/certs/server.crt",
			keyFile:  "/etc/ssl/private/server.key",
			tlsReady: true,
		},
		{
			name:     "cert missing – plain-text would be required",
			certFile: "",
			keyFile:  "/etc/ssl/private/server.key",
			tlsReady: false,
		},
		{
			name:     "key missing – plain-text would be required",
			certFile: "/etc/ssl/certs/server.crt",
			keyFile:  "",
			tlsReady: false,
		},
		{
			name:     "both missing – plain-text would be required",
			certFile: "",
			keyFile:  "",
			tlsReady: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ServerPort:  ":8081",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}

			// This logic mirrors the guard in cmd/server/main.go.
			ready := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if ready != tc.tlsReady {
				t.Errorf("TLS readiness: expected %v, got %v (cert=%q, key=%q)",
					tc.tlsReady, ready, tc.certFile, tc.keyFile)
			}
		})
	}
}

// TestGetEnv_ReturnsDefaultWhenUnset verifies the helper falls back to the
// default value when the environment variable is absent.
func TestGetEnv_ReturnsDefaultWhenUnset(t *testing.T) {
	const key = "TEST_GETENV_UNSET_12345"
	os.Unsetenv(key)

	got := getEnv(key, "default_value")
	if got != "default_value" {
		t.Errorf("expected %q, got %q", "default_value", got)
	}
}

// TestGetEnv_ReturnsEnvValueWhenSet verifies the helper returns the actual
// environment variable value when present.
func TestGetEnv_ReturnsEnvValueWhenSet(t *testing.T) {
	const key = "TEST_GETENV_SET_12345"
	os.Setenv(key, "env_value")
	defer os.Unsetenv(key)

	got := getEnv(key, "default_value")
	if got != "env_value" {
		t.Errorf("expected %q, got %q", "env_value", got)
	}
}
