package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that default configuration values are
// populated when no environment variables are set.
func TestLoad_DefaultValues(t *testing.T) {
	// Ensure TLS env vars are not set during this test.
	clearTLSEnv(t)

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, ":8081")
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile: got %q, want empty string", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile: got %q, want empty string", cfg.TLSKeyFile)
	}
	if cfg.TLSInsecure != "" {
		t.Errorf("TLSInsecure: got %q, want empty string", cfg.TLSInsecure)
	}
}

// TestLoad_TLSEnvVars verifies that TLS configuration is read from environment
// variables when they are set.
func TestLoad_TLSEnvVars(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("TLSCertFile: got %q, want %q", cfg.TLSCertFile, "/etc/ssl/certs/server.crt")
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("TLSKeyFile: got %q, want %q", cfg.TLSKeyFile, "/etc/ssl/private/server.key")
	}
}

// TestLoad_TLSInsecureEnvVar verifies that the TLS_INSECURE flag is read from
// the environment variable.
func TestLoad_TLSInsecureEnvVar(t *testing.T) {
	clearTLSEnv(t)
	t.Setenv("TLS_INSECURE", "true")

	cfg := Load()

	if cfg.TLSInsecure != "true" {
		t.Errorf("TLSInsecure: got %q, want %q", cfg.TLSInsecure, "true")
	}
}

// TestTLSEnabled_BothSet verifies TLSEnabled returns true when both cert and
// key paths are configured — this is the production-safe TLS path.
func TestTLSEnabled_BothSet(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "/path/to/cert.pem",
		TLSKeyFile:  "/path/to/key.pem",
	}

	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() = false; want true when both TLSCertFile and TLSKeyFile are set")
	}
}

// TestTLSEnabled_OnlyCert verifies TLSEnabled returns false when only the
// certificate is provided (key is missing). This prevents a partial TLS
// configuration from being treated as fully enabled.
func TestTLSEnabled_OnlyCert(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "/path/to/cert.pem",
		TLSKeyFile:  "",
	}

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true; want false when TLSKeyFile is empty")
	}
}

// TestTLSEnabled_OnlyKey verifies TLSEnabled returns false when only the
// private key is provided (certificate is missing).
func TestTLSEnabled_OnlyKey(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "",
		TLSKeyFile:  "/path/to/key.pem",
	}

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true; want false when TLSCertFile is empty")
	}
}

// TestTLSEnabled_NeitherSet verifies TLSEnabled returns false when neither
// the certificate nor the key are provided — the server must refuse to start
// without the TLS_INSECURE override.
func TestTLSEnabled_NeitherSet(t *testing.T) {
	cfg := &Config{
		TLSCertFile: "",
		TLSKeyFile:  "",
	}

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true; want false when both TLSCertFile and TLSKeyFile are empty")
	}
}

// TestTLSEnabled_EmptyStrings verifies TLSEnabled treats whitespace-only or
// absent values as "not configured" — guards against accidentally passing
// empty env var values that would incorrectly enable TLS.
func TestTLSEnabled_EmptyStrings(t *testing.T) {
	cases := []struct {
		cert string
		key  string
	}{
		{"", ""},
		{"", "/key.pem"},
		{"/cert.pem", ""},
	}

	for _, tc := range cases {
		cfg := &Config{TLSCertFile: tc.cert, TLSKeyFile: tc.key}
		if cfg.TLSEnabled() {
			t.Errorf("TLSEnabled() = true for cert=%q key=%q; want false", tc.cert, tc.key)
		}
	}
}

// TestLoad_ServerPortEnvVar verifies that the SERVER_PORT environment variable
// overrides the default port.
func TestLoad_ServerPortEnvVar(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, ":9443")
	}
}

// TestLoad_AllTLSEnvVarsSet verifies a fully configured TLS setup is properly
// loaded — both cert and key present, TLSEnabled must return true, and
// TLSInsecure flag is not needed.
func TestLoad_AllTLSEnvVarsSet(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/certs/server.crt")
	t.Setenv("TLS_KEY_FILE", "/certs/server.key")
	t.Setenv("TLS_INSECURE", "")

	cfg := Load()

	if !cfg.TLSEnabled() {
		t.Error("TLSEnabled() = false; want true when TLS_CERT_FILE and TLS_KEY_FILE are set")
	}
	if cfg.TLSInsecure != "" {
		t.Errorf("TLSInsecure: got %q, want empty string", cfg.TLSInsecure)
	}
}

// TestLoad_TLSInsecureDoesNotEnableTLS verifies that setting TLS_INSECURE=true
// alone (without cert/key paths) does NOT make TLSEnabled return true.
// TLS_INSECURE is purely a gate for the plain-HTTP fallback; it must never
// be confused with actual TLS being enabled.
func TestLoad_TLSInsecureDoesNotEnableTLS(t *testing.T) {
	clearTLSEnv(t)
	t.Setenv("TLS_INSECURE", "true")

	cfg := Load()

	if cfg.TLSEnabled() {
		t.Error("TLSEnabled() = true; want false — TLS_INSECURE=true must not be treated as TLS enabled")
	}
}

// clearTLSEnv removes TLS-related environment variables for the duration of
// the test and restores the original values on cleanup.
func clearTLSEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"TLS_CERT_FILE", "TLS_KEY_FILE", "TLS_INSECURE"} {
		original, exists := os.LookupEnv(key)
		os.Unsetenv(key)
		if exists {
			t.Cleanup(func() { os.Setenv(key, original) })
		}
	}
}
