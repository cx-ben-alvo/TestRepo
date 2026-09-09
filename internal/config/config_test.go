package config

import (
	"os"
	"testing"
)

// TestLoad_TLSFieldsDefaultToEmpty verifies that TLS cert/key paths default
// to empty strings when environment variables are not set, ensuring the
// server cannot accidentally start without TLS configured.
func TestLoad_TLSFieldsDefaultToEmpty(t *testing.T) {
	// Clear TLS env vars to simulate an unconfigured environment.
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to default to empty string, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to default to empty string, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSCertFileFromEnv verifies that TLS_CERT_FILE env var is read
// correctly, ensuring the TLS certificate path can be configured.
func TestLoad_TLSCertFileFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/certs/server.crt"
	os.Setenv("TLS_CERT_FILE", certPath)
	defer os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile %q, got %q", certPath, cfg.TLSCertFile)
	}
}

// TestLoad_TLSKeyFileFromEnv verifies that TLS_KEY_FILE env var is read
// correctly, ensuring the TLS private key path can be configured.
func TestLoad_TLSKeyFileFromEnv(t *testing.T) {
	const keyPath = "/etc/ssl/private/server.key"
	os.Unsetenv("TLS_CERT_FILE")
	os.Setenv("TLS_KEY_FILE", keyPath)
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_BothTLSFieldsFromEnv verifies that both TLS cert and key paths
// can be independently set via environment variables.
func TestLoad_BothTLSFieldsFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/certs/server.crt"
	const keyPath = "/etc/ssl/private/server.key"

	os.Setenv("TLS_CERT_FILE", certPath)
	os.Setenv("TLS_KEY_FILE", keyPath)
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsRequiredTogether verifies that when only one TLS field
// is set the other remains empty, making it easy to detect a misconfiguration
// where both fields are not provided.
func TestLoad_TLSFieldsRequiredTogether(t *testing.T) {
	cases := []struct {
		name         string
		certFile     string
		keyFile      string
		wantBothFull bool
	}{
		{
			name:         "only cert set",
			certFile:     "/tmp/cert.pem",
			keyFile:      "",
			wantBothFull: false,
		},
		{
			name:         "only key set",
			certFile:     "",
			keyFile:      "/tmp/key.pem",
			wantBothFull: false,
		},
		{
			name:         "both set",
			certFile:     "/tmp/cert.pem",
			keyFile:      "/tmp/key.pem",
			wantBothFull: true,
		},
		{
			name:         "neither set",
			certFile:     "",
			keyFile:      "",
			wantBothFull: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear first to avoid leakage between sub-tests.
			os.Unsetenv("TLS_CERT_FILE")
			os.Unsetenv("TLS_KEY_FILE")

			if tc.certFile != "" {
				os.Setenv("TLS_CERT_FILE", tc.certFile)
				defer os.Unsetenv("TLS_CERT_FILE")
			}
			if tc.keyFile != "" {
				os.Setenv("TLS_KEY_FILE", tc.keyFile)
				defer os.Unsetenv("TLS_KEY_FILE")
			}

			cfg := Load()

			// Both fields must be non-empty for the server to start securely.
			bothFull := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
			if bothFull != tc.wantBothFull {
				t.Errorf("wantBothFull=%v but got TLSCertFile=%q TLSKeyFile=%q",
					tc.wantBothFull, cfg.TLSCertFile, cfg.TLSKeyFile)
			}
		})
	}
}

// TestLoad_ServerPortDefault verifies the server port default is unchanged
// and that pre-existing config fields still load correctly after the TLS
// fields were added.
func TestLoad_ServerPortDefault(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort ':8081', got %q", cfg.ServerPort)
	}
}

// TestLoad_ServerPortFromEnv verifies the server port can be overridden.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort ':9443', got %q", cfg.ServerPort)
	}
}
