package config

import (
	"os"
	"testing"
)

// TestLoad_TLSFieldsFromEnv verifies that TLSCertFile and TLSKeyFile are
// loaded from the TLS_CERT_FILE and TLS_KEY_FILE environment variables.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/ssl/certs/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/ssl/private/server.key")
	defer os.Unsetenv("TLS_CERT_FILE")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "/etc/ssl/certs/server.crt" {
		t.Errorf("expected TLSCertFile=/etc/ssl/certs/server.crt, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/ssl/private/server.key" {
		t.Errorf("expected TLSKeyFile=/etc/ssl/private/server.key, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsDefaultToEmpty verifies that TLSCertFile and TLSKeyFile
// default to empty strings when the environment variables are not set,
// preventing accidental plain-text server startup without TLS configuration.
func TestLoad_TLSFieldsDefaultToEmpty(t *testing.T) {
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

// TestLoad_ServerPortFromEnv verifies that ServerPort is loaded from the
// SERVER_PORT environment variable.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	os.Setenv("SERVER_PORT", ":9443")
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort=:9443, got %q", cfg.ServerPort)
	}
}

// TestLoad_ServerPortDefaultValue verifies the default server port.
func TestLoad_ServerPortDefaultValue(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != ":8081" {
		t.Errorf("expected default ServerPort=:8081, got %q", cfg.ServerPort)
	}
}

// TestLoad_TLSRequiredCheck validates the intended guard: when TLS_CERT_FILE
// or TLS_KEY_FILE is absent, cfg fields are empty, signalling that the server
// must reject startup rather than fall back to plain HTTP.
func TestLoad_TLSRequiredCheck(t *testing.T) {
	tests := []struct {
		name        string
		certEnv     string
		keyEnv      string
		wantTLSReady bool
	}{
		{
			name:         "both TLS vars set — TLS ready",
			certEnv:      "/path/to/cert.pem",
			keyEnv:       "/path/to/key.pem",
			wantTLSReady: true,
		},
		{
			name:         "cert missing — TLS NOT ready",
			certEnv:      "",
			keyEnv:       "/path/to/key.pem",
			wantTLSReady: false,
		},
		{
			name:         "key missing — TLS NOT ready",
			certEnv:      "/path/to/cert.pem",
			keyEnv:       "",
			wantTLSReady: false,
		},
		{
			name:         "both missing — TLS NOT ready",
			certEnv:      "",
			keyEnv:       "",
			wantTLSReady: false,
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
			tlsReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""

			if tlsReady != tc.wantTLSReady {
				t.Errorf("TLS readiness: got %v, want %v (cert=%q, key=%q)",
					tlsReady, tc.wantTLSReady, cfg.TLSCertFile, cfg.TLSKeyFile)
			}
		})
	}
}
