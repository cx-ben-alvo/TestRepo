package config

import "os"

// Config holds application configuration
type Config struct {
	ServerPort  string
	CloneDir    string
	DownloadDir string
	// TLSCertFile is the path to the TLS certificate file (PEM format).
	// Required for HTTPS/TLS transport.
	TLSCertFile string
	// TLSKeyFile is the path to the TLS private key file (PEM format).
	// Required for HTTPS/TLS transport.
	TLSKeyFile string
}

// Load loads configuration from environment variables or defaults
func Load() *Config {
	return &Config{
		ServerPort:  getEnv("SERVER_PORT", ":8081"),
		CloneDir:    getEnv("CLONE_DIR", "/Users/benalvo/clones"),
		DownloadDir: getEnv("DOWNLOAD_DIR", "/Users/benalvo/downloads"),
		// TLS_CERT_FILE and TLS_KEY_FILE must be set to valid certificate and
		// key paths before the server will start.  There are no insecure defaults.
		TLSCertFile: getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getEnv("TLS_KEY_FILE", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
