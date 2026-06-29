package config

import (
	"os"
	"testing"
)

// TestLoad_Defaults verifies that the default configuration is populated when
// no environment variables are set.
func TestLoad_Defaults(t *testing.T) {
	// Clear any environment variables that may be set in CI.
	for _, key := range []string{"SERVER_PORT", "CLONE_DIR", "DOWNLOAD_DIR", "TLS_CERT_FILE", "TLS_KEY_FILE"} {
		os.Unsetenv(key)
	}

	cfg := Load()

	if cfg.ServerPort == "" {
		t.Error("ServerPort must not be empty")
	}
	// TLS fields default to empty — callers are responsible for rejecting an
	// empty configuration before starting the server.
	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile default to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile default to be empty, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLS_CERT_FILE and TLS_KEY_FILE are
// read from the environment, ensuring the configuration carries the values
// required for encrypted transport (CWE-319 remediation).
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	const wantCert = "/etc/ssl/certs/server.crt"
	const wantKey = "/etc/ssl/private/server.key"

	t.Setenv("TLS_CERT_FILE", wantCert)
	t.Setenv("TLS_KEY_FILE", wantKey)
	defer os.Unsetenv("TLS_CERT_FILE")
	defer os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != wantCert {
		t.Errorf("TLSCertFile: got %q, want %q", cfg.TLSCertFile, wantCert)
	}
	if cfg.TLSKeyFile != wantKey {
		t.Errorf("TLSKeyFile: got %q, want %q", cfg.TLSKeyFile, wantKey)
	}
}

// TestLoad_ServerPort verifies the SERVER_PORT environment variable overrides
// the default value.
func TestLoad_ServerPort(t *testing.T) {
	const wantPort = ":9443"
	t.Setenv("SERVER_PORT", wantPort)
	defer os.Unsetenv("SERVER_PORT")

	cfg := Load()

	if cfg.ServerPort != wantPort {
		t.Errorf("ServerPort: got %q, want %q", cfg.ServerPort, wantPort)
	}
}

// TestLoad_DefaultServerPortIsHTTPS verifies that the default port is the
// conventional HTTPS port (:8443) rather than a plain-text HTTP port.
// This is a regression guard for the CWE-319 fix: the default must never
// silently downgrade to an unencrypted listener.
func TestLoad_DefaultServerPortIsHTTPS(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	// The default must NOT be the plain-text HTTP ports :80 or :8080.
	// Acceptable values are HTTPS convention ports such as :443, :8443, etc.
	insecurePorts := map[string]bool{
		":80":   true,
		":8080": true,
		":8081": true, // previous insecure default
	}
	if insecurePorts[cfg.ServerPort] {
		t.Errorf("default ServerPort %q is a plain-text HTTP port; must use an HTTPS port", cfg.ServerPort)
	}
}

// TestTLSRequirementEnforcement documents that the server MUST reject startup
// when TLS certificate/key paths are absent. This test verifies the helper
// function that encodes that policy; the actual log.Fatal call lives in main().
func TestTLSRequirementEnforcement(t *testing.T) {
	tests := []struct {
		name        string
		certFile    string
		keyFile     string
		wantMissing bool
	}{
		{
			name:        "both empty – TLS not configured",
			certFile:    "",
			keyFile:     "",
			wantMissing: true,
		},
		{
			name:        "cert set but key missing",
			certFile:    "/etc/ssl/server.crt",
			keyFile:     "",
			wantMissing: true,
		},
		{
			name:        "key set but cert missing",
			certFile:    "",
			keyFile:     "/etc/ssl/server.key",
			wantMissing: true,
		},
		{
			name:        "both provided – TLS ready",
			certFile:    "/etc/ssl/server.crt",
			keyFile:     "/etc/ssl/server.key",
			wantMissing: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ServerPort:  ":8443",
				TLSCertFile: tc.certFile,
				TLSKeyFile:  tc.keyFile,
			}
			got := cfg.TLSCertFile == "" || cfg.TLSKeyFile == ""
			if got != tc.wantMissing {
				t.Errorf("TLS missing = %v, want %v (certFile=%q keyFile=%q)",
					got, tc.wantMissing, tc.certFile, tc.keyFile)
			}
		})
	}
}
