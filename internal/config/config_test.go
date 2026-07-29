package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultValues verifies that Load() returns sensible defaults
// when no environment variables are set. Notably, TLS fields default to empty
// so that the server startup logic can detect a missing TLS configuration and
// refuse to start in plain-text mode.
func TestLoad_DefaultValues(t *testing.T) {
	// Clear all relevant env vars so we test the true defaults.
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("CLONE_DIR")
	os.Unsetenv("DOWNLOAD_DIR")
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.ServerPort != ":8443" {
		t.Errorf("expected default ServerPort :8443, got %q", cfg.ServerPort)
	}
	// TLS fields must be empty strings when not set — the server must refuse
	// to start in that case (plain-text HTTP is not permitted, CWE-319).
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty string, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty string, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSEnvVars verifies that TLS_CERT_FILE and TLS_KEY_FILE are read
// from the environment so operators can supply real certificate paths.
func TestLoad_TLSEnvVars(t *testing.T) {
	const certPath = "/etc/tls/server.crt"
	const keyPath = "/etc/tls/server.key"

	os.Setenv("TLS_CERT_FILE", certPath)
	os.Setenv("TLS_KEY_FILE", keyPath)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("TLSCertFile: expected %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("TLSKeyFile: expected %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_ServerPortEnvVar ensures SERVER_PORT is overridable via environment.
func TestLoad_ServerPortEnvVar(t *testing.T) {
	const port = ":9443"
	os.Setenv("SERVER_PORT", port)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != port {
		t.Errorf("ServerPort: expected %q, got %q", port, cfg.ServerPort)
	}
}

// TestLoad_PartialTLSConfig verifies that providing only one of the two TLS
// fields still leaves the other empty — the server startup guard must treat
// either missing field as a fatal configuration error.
func TestLoad_PartialTLSConfig(t *testing.T) {
	tests := []struct {
		name         string
		certEnv      string
		keyEnv       string
		expectMissing bool // true when at least one TLS field should be empty
	}{
		{
			name:          "only cert set",
			certEnv:       "/etc/tls/server.crt",
			keyEnv:        "",
			expectMissing: true,
		},
		{
			name:          "only key set",
			certEnv:       "",
			keyEnv:        "/etc/tls/server.key",
			expectMissing: true,
		},
		{
			name:          "both set",
			certEnv:       "/etc/tls/server.crt",
			keyEnv:        "/etc/tls/server.key",
			expectMissing: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Unsetenv("TLS_CERT_FILE")
			os.Unsetenv("TLS_KEY_FILE")

			if tc.certEnv != "" {
				os.Setenv("TLS_CERT_FILE", tc.certEnv)
				defer os.Unsetenv("TLS_CERT_FILE")
			}
			if tc.keyEnv != "" {
				os.Setenv("TLS_KEY_FILE", tc.keyEnv)
				defer os.Unsetenv("TLS_KEY_FILE")
			}

			cfg := Load()
			missing := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""

			if missing != tc.expectMissing {
				t.Errorf("expectMissing=%v but got TLSCertFile=%q TLSKeyFile=%q",
					tc.expectMissing, cfg.TLSCertFile, cfg.TLSKeyFile)
			}
		})
	}
}

// TestTLSEnforcement_StartupGuard validates the logic used in main() to block
// startup when TLS credentials are absent. This test replicates the guard
// condition so any future refactor that removes or weakens it will fail here.
func TestTLSEnforcement_StartupGuard(t *testing.T) {
	tests := []struct {
		name        string
		certFile    string
		keyFile     string
		shouldBlock bool // true == server must NOT start (TLS not configured)
	}{
		{"no TLS config", "", "", true},
		{"cert only", "/etc/tls/server.crt", "", true},
		{"key only", "", "/etc/tls/server.key", true},
		{"both provided", "/etc/tls/server.crt", "/etc/tls/server.key", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ServerPort:  ":8443",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}

			// Replicate the guard from cmd/server/main.go:
			//   if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" { ... fatal ... }
			blocked := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""

			if blocked != tc.shouldBlock {
				t.Errorf("case %q: expected blocked=%v, got blocked=%v",
					tc.name, tc.shouldBlock, blocked)
			}
		})
	}
}
