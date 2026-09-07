package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultTLSFieldsAreEmpty verifies that when the TLS_CERT_FILE and
// TLS_KEY_FILE environment variables are absent the Config fields are empty
// strings, which causes the server to refuse to start without TLS configured.
func TestLoad_DefaultTLSFieldsAreEmpty(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Fatalf("TLSCertFile = %q; want empty string when TLS_CERT_FILE is unset", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Fatalf("TLSKeyFile = %q; want empty string when TLS_KEY_FILE is unset", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsReadFromEnvironment verifies that TLS_CERT_FILE and
// TLS_KEY_FILE environment variables are correctly loaded into Config.
// This ensures the server can be configured to use HTTPS (CWE-319 fix).
func TestLoad_TLSFieldsReadFromEnvironment(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", wantCert)
	os.Setenv("TLS_KEY_FILE", wantKey)
	defer os.Unsetenv("TLS_CERT_FILE")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Fatalf("TLSCertFile = %q; want %q", cfg.TLSCertFile, wantCert)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Fatalf("TLSKeyFile = %q; want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoad_ServerPortDefaultValue confirms the default server port is still
// correctly loaded to avoid regressions in the non-TLS config fields.
func TestLoad_ServerPortDefaultValue(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Fatalf("ServerPort = %q; want \":8081\"", cfg.ServerPort)
	}
}

// TestLoad_ServerPortFromEnvironment confirms that SERVER_PORT is honoured
// when set via the environment.
func TestLoad_ServerPortFromEnvironment(t *testing.T) {
	const wantPort = ":9443"
	os.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Fatalf("ServerPort = %q; want %q", cfg.ServerPort, wantPort)
	}
}

// TestLoad_TLSBothFieldsMustBeSetForTLS documents the security contract: both
// TLSCertFile and TLSKeyFile must be non-empty for the server to start with
// TLS. A config that has only one field set should be treated as misconfigured.
func TestLoad_TLSBothFieldsMustBeSetForTLS(t *testing.T) {
	tests := []struct {
		name        string
		certEnv     string
		keyEnv      string
		wantReady   bool // both fields non-empty
	}{
		{
			name:      "neither set — not TLS ready",
			certEnv:   "",
			keyEnv:    "",
			wantReady: false,
		},
		{
			name:      "only cert set — not TLS ready",
			certEnv:   "/path/to/cert.pem",
			keyEnv:    "",
			wantReady: false,
		},
		{
			name:      "only key set — not TLS ready",
			certEnv:   "",
			keyEnv:    "/path/to/key.pem",
			wantReady: false,
		},
		{
			name:      "both set — TLS ready",
			certEnv:   "/path/to/cert.pem",
			keyEnv:    "/path/to/key.pem",
			wantReady: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.certEnv != "" {
				os.Setenv("TLS_CERT_FILE", tc.certEnv)
			} else {
				os.Unsetenv("TLS_CERT_FILE")
			}
			if tc.keyEnv != "" {
				os.Setenv("TLS_KEY_FILE", tc.keyEnv)
			} else {
				os.Unsetenv("TLS_KEY_FILE")
			}
			defer os.Unsetenv("TLS_CERT_FILE")
			defer os.Unsetenv("TLS_KEY_FILE")

			cfg := Load()

			gotReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if gotReady != tc.wantReady {
				t.Fatalf("TLS readiness = %v (cert=%q, key=%q); want %v",
					gotReady, cfg.TLSCertFile, cfg.TLSKeyFile, tc.wantReady)
			}
		})
	}
}
