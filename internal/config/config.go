package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	// TLSCertFile and TLSKeyFile must be set to enable HTTPS (TLS).
	// When both are provided the server listens over TLS; when either is
	// absent the server refuses to start unless TLSInsecure is explicitly
	// set to "true" (development-only override).
	TLSCertFile string
	TLSKeyFile  string
	TLSInsecure string
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8081"),
		CloneDir:    getEnv("CLONE_DIR", "/Users/benalvo/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/Users/benalvo/downloads"),
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
		// TLS_INSECURE=true disables TLS for local development only.
		// Must NEVER be set in production environments.
		TLSInsecure: getEnv("TLS_INSECURE", ""),
	}
}

// TLSEnabled reports whether TLS is fully configured.
func (c *Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
