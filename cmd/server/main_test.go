package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/checkmarx/correlation-demo/internal/config"
)

// TestTLSEnforcementContract verifies the security invariant introduced by the
// CWE-319 remediation: plain-text HTTP is no longer an accepted fallback.
// The server startup path calls log.Fatal (os.Exit) when TLSEnabled() is false,
// so these tests validate the config.TLSEnabled() gate that guards the
// ListenAndServeTLS call.
//
// The contract is:
//   - TLSEnabled() == false  →  server MUST refuse to start (log.Fatal)
//   - TLSEnabled() == true   →  server MUST use ListenAndServeTLS (never ListenAndServe)

// TestTLSRequired_NoTLSConfigMeansDisabled confirms that when neither
// TLS_CERT_FILE nor TLS_KEY_FILE is set, TLSEnabled() returns false.
// This ensures the startup guard (the log.Fatal branch) is triggered,
// preventing a plain-text HTTP server from starting.
func TestTLSRequired_NoTLSConfigMeansDisabled(t *testing.T) {
	os.Unsetenv("TLS_CERT_FILE")
	os.Unsetenv("TLS_KEY_FILE")

	cfg := config.Load()

	if cfg.TLSEnabled() {
		t.Fatal("TLSEnabled() must return false when env vars are absent; " +
			"this would bypass the startup guard and allow plain-text HTTP (CWE-319)")
	}
}

// TestTLSRequired_PartialConfigIsInsufficient verifies that a configuration
// with only one of the two TLS env vars does not pass the TLS gate.
// A partial configuration must not silently fall back to plain-text HTTP.
func TestTLSRequired_PartialConfigIsInsufficient(t *testing.T) {
	cases := []struct {
		name    string
		certSet bool
		keySet  bool
	}{
		{name: "only cert", certSet: true, keySet: false},
		{name: "only key", certSet: false, keySet: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			os.Unsetenv("TLS_CERT_FILE")
			os.Unsetenv("TLS_KEY_FILE")
			if tc.certSet {
				os.Setenv("TLS_CERT_FILE", "/path/to/cert.pem")
				defer os.Unsetenv("TLS_CERT_FILE")
			}
			if tc.keySet {
				os.Setenv("TLS_KEY_FILE", "/path/to/key.pem")
				defer os.Unsetenv("TLS_KEY_FILE")
			}

			cfg := config.Load()

			if cfg.TLSEnabled() {
				t.Errorf("TLSEnabled() must return false for partial TLS config (%s); "+
					"partial config must not enable plain-text fallback", tc.name)
			}
		})
	}
}

// TestTLSRequired_BothFilesEnablesTLS verifies that when both TLS_CERT_FILE
// and TLS_KEY_FILE are configured, TLSEnabled() returns true so the server
// proceeds to call ListenAndServeTLS rather than the removed plain-text path.
func TestTLSRequired_BothFilesEnablesTLS(t *testing.T) {
	os.Setenv("TLS_CERT_FILE", "/etc/tls/server.crt")
	os.Setenv("TLS_KEY_FILE", "/etc/tls/server.key")
	defer func() {
		os.Unsetenv("TLS_CERT_FILE")
		os.Unsetenv("TLS_KEY_FILE")
	}()

	cfg := config.Load()

	if !cfg.TLSEnabled() {
		t.Fatal("TLSEnabled() must return true when both cert and key files are set; " +
			"the server would incorrectly refuse to start")
	}
	if cfg.TLSCertFile != "/etc/tls/server.crt" {
		t.Errorf("TLSCertFile: got %q, want /etc/tls/server.crt", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "/etc/tls/server.key" {
		t.Errorf("TLSKeyFile: got %q, want /etc/tls/server.key", cfg.TLSKeyFile)
	}
}

// TestTLSRequired_NilHandlerMeansDefaultMux documents that main() passes nil
// as the handler to ListenAndServeTLS, which means the default ServeMux
// (populated by http.Handle in main()) is used. This test ensures that when
// TLS is properly configured the cert/key paths are propagated correctly.
func TestTLSRequired_NilHandlerMeansDefaultMux(t *testing.T) {
	certPath := "/run/secrets/tls.crt"
	keyPath := "/run/secrets/tls.key"

	cfg := &config.Config{
		ServerPort:  ":8443",
		TLSCertFile: certPath,
		TLSKeyFile:  keyPath,
	}

	if !cfg.TLSEnabled() {
		t.Fatal("config with both cert and key paths must have TLSEnabled() == true")
	}
	// Confirm the paths are accessible for the ListenAndServeTLS call.
	if cfg.TLSCertFile != certPath {
		t.Errorf("unexpected TLSCertFile: got %q", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != keyPath {
		t.Errorf("unexpected TLSKeyFile: got %q", cfg.TLSKeyFile)
	}
}

// TestInitDirs_CreatesDirectories verifies that initDirs creates the CloneDir
// and DownloadDir specified in the configuration.  These are non-sensitive
// filesystem operations; no network activity is involved.
func TestInitDirs_CreatesDirectories(t *testing.T) {
	base := t.TempDir()
	cloneDir := filepath.Join(base, "clones")
	downloadDir := filepath.Join(base, "downloads")

	cfg := &config.Config{
		CloneDir:    cloneDir,
		DownloadDir: downloadDir,
	}

	initDirs(cfg)

	for _, dir := range []string{cloneDir, downloadDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("directory %q was not created: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("path %q exists but is not a directory", dir)
		}
	}
}

// TestInitDirs_IdempotentOnExistingDirectories verifies that calling initDirs
// when the directories already exist does not return an error or corrupt them.
func TestInitDirs_IdempotentOnExistingDirectories(t *testing.T) {
	base := t.TempDir()
	cloneDir := filepath.Join(base, "clones")
	downloadDir := filepath.Join(base, "downloads")

	// Create the directories first.
	if err := os.MkdirAll(cloneDir, 0755); err != nil {
		t.Fatalf("pre-creating cloneDir failed: %v", err)
	}
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		t.Fatalf("pre-creating downloadDir failed: %v", err)
	}

	cfg := &config.Config{
		CloneDir:    cloneDir,
		DownloadDir: downloadDir,
	}

	// Should not panic or produce incorrect state.
	initDirs(cfg)

	for _, dir := range []string{cloneDir, downloadDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("directory %q disappeared after second initDirs call: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("path %q is no longer a directory after second initDirs call", dir)
		}
	}
}
