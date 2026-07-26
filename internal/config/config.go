package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	// TLS configuration — required for secure HTTPS transport (CWE-319)
	TLSCertFile string
	TLSKeyFile  string
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8443"),
		CloneDir:    getEnv("CLONE_DIR", "/Users/benalvo/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/Users/benalvo/downloads"),
		// TLS_CERT_FILE and TLS_KEY_FILE must be set to valid PEM-encoded
		// certificate and private key files before starting the server.
		TLSCertFile: getEnv("TLS_CERT_FILE", "server.crt"),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", "server.key"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
