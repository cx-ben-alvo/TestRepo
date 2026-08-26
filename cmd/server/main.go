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

	// Register routes — all wrapped with WithSecurityHeaders to ensure the
	// Content-Security-Policy header is present on every response (CWE-346).
	http.HandleFunc("/api/repo/create", handler.WithSecurityHeaders(h.CreateRepo))
	http.HandleFunc("/api/repo/clone", handler.WithSecurityHeaders(h.CloneRepo))
	http.HandleFunc("/api/repo/list", handler.WithSecurityHeaders(h.ListRepos))

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// Require TLS certificate and key to protect data in transit (CWE-319).
	// Set TLS_CERT_FILE and TLS_KEY_FILE environment variables to paths of a
	// valid PEM-encoded certificate and private key respectively.
	// Serving over plain HTTP exposes all traffic to man-in-the-middle attacks.
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE must be set; refusing to start without TLS")
	}
	log.Printf("Starting HTTPS server on %s", cfg.ServerPort)
	log.Fatal(http.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
