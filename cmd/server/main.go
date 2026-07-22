package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/checkmarx/correlation-demo/internal/config"
	"github.com/checkmarx/correlation-demo/internal/database"
	"github.com/checkmarx/correlation-demo/internal/handler"
	"github.com/checkmarx/correlation-demo/internal/repository"
	"github.com/checkmarx/correlation-demo/internal/service"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize directories
	initDirs(cfg)

	// Initialize database
	db, err := database.InitDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Initialize dependencies
	repoStore := repository.NewRepositoryStore(db)
	validator := service.NewDomainValidator()
	gitService := service.NewGitService(cfg.CloneDir)

	// Initialize handler
	h := handler.NewHandler(repoStore, validator, gitService)

	// Register routes
	http.HandleFunc("/api/repo/create", h.CreateRepo)
	http.HandleFunc("/api/repo/clone", h.CloneRepo)
	http.HandleFunc("/api/repo/list", h.ListRepos)

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// TLS is required to protect data in transit (CWE-319).
	// Set TLS_CERT_FILE and TLS_KEY_FILE environment variables to provide
	// the certificate and key paths before starting the server.
	if err := requireTLS(cfg); err != nil {
		log.Fatal(err)
	}

	fmt.Println("TLS enabled: serving over HTTPS")
	log.Fatal(http.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
}

// requireTLS enforces that TLS must be configured before the server starts.
// It returns an error when TLS certificate and key paths are not both provided,
// preventing the server from falling back to plain-text HTTP (CWE-319).
func requireTLS(cfg *config.Config) error {
	if !cfg.TLSEnabled() {
		return fmt.Errorf("TLS is required: set TLS_CERT_FILE and TLS_KEY_FILE environment variables")
	}
	return nil
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
