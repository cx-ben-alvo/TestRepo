package config

import (
	"os"
	"testing"
)

// TestLoad_DefaultsTLSFields verifies that TLSCertFile and TLSKeyFile default to
// empty strings when the corresponding environment variables are not set, ensuring
// the server cannot start without explicit TLS configuration.
func TestLoad_DefaultsTLSFields(t *testing.T) {
	// Ensure env vars are not set
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty by default, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty by default, got %q", cfg.TLSKeyFile)
	}
}

// TestLoad_TLSFieldsFromEnv verifies that TLSCertFile and TLSKeyFile are correctly
// loaded from environment variables, so operators can supply cert/key paths at runtime.
func TestLoad_TLSFieldsFromEnv(t *testing.T) {
	const certPath = "/etc/ssl/certs/server.crt"
	const keyPath = "/etc/ssl/private/server.key"

	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_KEY_FILE", keyPath)

	cfg := Load()

	if cfg.TLSCertFile != certPath {
		t.Errorf("expected TLSCertFile %q, got %q", certPath, cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("expected TLSKeyFile %q, got %q", keyPath, cfg.TLSKeyFile)
	}
}

// TestLoad_DefaultServerPort verifies that the default server port is :8443,
// which is the conventional HTTPS port and reflects the shift from plain HTTP.
func TestLoad_DefaultServerPort(t *testing.T) {
	os.Unsetenv("SERVER_PORT")

	cfg := Load()

	const wantPort = ":8443"
	if cfg.ServerPort != wantPort {
		t.Errorf("expected default ServerPort %q, got %q", wantPort, cfg.ServerPort)
	}
}

// TestLoad_ServerPortFromEnv verifies that the server port is overridable via
// SERVER_PORT environment variable.
func TestLoad_ServerPortFromEnv(t *testing.T) {
	t.Setenv("SERVER_PORT", ":9443")

	cfg := Load()

	if cfg.ServerPort != ":9443" {
		t.Errorf("expected ServerPort :9443, got %q", cfg.ServerPort)
	}
}

// TestLoad_AllFields verifies that all configuration fields can be set via
// environment variables and are reflected correctly in the loaded Config.
func TestLoad_AllFields(t *testing.T) {
	t.Setenv("SERVER_PORT", ":8443")
	t.Setenv("CLONE_DIR", "/tmp/clones")
	t.Setenv("DOWNLOAD_DIR", "/tmp/downloads")
	t.Setenv("TLS_CERT_FILE", "/certs/server.crt")
	t.Setenv("TLS_KEY_FILE", "/certs/server.key")

	cfg := Load()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"ServerPort", cfg.ServerPort, ":8443"},
		{"CloneDir", cfg.CloneDir, "/tmp/clones"},
		{"DownloadDir", cfg.DownloadDir, "/tmp/downloads"},
		{"TLSCertFile", cfg.TLSCertFile, "/certs/server.crt"},
		{"TLSKeyFile", cfg.TLSKeyFile, "/certs/server.key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("expected %s=%q, got %q", tc.name, tc.want, tc.got)
			}
		})
	}
}

// TestLoad_TLSBothEmpty confirms that when both TLS env vars are absent, both
// fields remain empty — the server startup code uses this as the signal that
// TLS has not been configured and must refuse to start.
func TestLoad_TLSBothEmpty(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	tlsConfigured := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsConfigured {
		t.Error("expected TLS to be unconfigured when env vars are absent")
	}
}

// TestLoad_TLSPartialConfig_CertOnly tests that setting only TLS_CERT_FILE
// without TLS_KEY_FILE still results in an incomplete TLS configuration,
// which the server startup code should reject.
func TestLoad_TLSPartialConfig_CertOnly(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/certs/server.crt")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := Load()

	if cfg.TLSCertFile == "" {
		t.Error("expected TLSCertFile to be set")
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("expected TLSKeyFile to be empty, got %q", cfg.TLSKeyFile)
	}

	// Simulate the startup guard: both must be non-empty
	tlsReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsReady {
		t.Error("server should not be considered TLS-ready with only a cert file")
	}
}

// TestLoad_TLSPartialConfig_KeyOnly tests that setting only TLS_KEY_FILE
// without TLS_CERT_FILE results in an incomplete TLS configuration.
func TestLoad_TLSPartialConfig_KeyOnly(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	t.Setenv("TLS_KEY_FILE", "/certs/server.key")

	cfg := Load()

	if cfg.TLSCertFile != "" {
		t.Errorf("expected TLSCertFile to be empty, got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile == "" {
		t.Error("expected TLSKeyFile to be set")
	}

	tlsReady := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if tlsReady {
		t.Error("server should not be considered TLS-ready with only a key file")
	}
}
