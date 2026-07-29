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

	if cfg.TLSEnabled() {
		// Preferred path: serve over TLS to protect data in transit.
		log.Printf("Starting HTTPS server on %s (TLS enabled)", cfg.ServerPort)
		log.Fatal(http.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
	} else if cfg.TLSInsecure == "true" {
		// Development-only fallback: plain HTTP is intentionally insecure and
		// must never be used in production. Set TLS_CERT_FILE and TLS_KEY_FILE
		// environment variables to enable TLS.
		log.Printf("WARNING: TLS is disabled (TLS_INSECURE=true). " +
			"This must NOT be used in production. " +
			"Set TLS_CERT_FILE and TLS_KEY_FILE to enable TLS.")
		log.Fatal(http.ListenAndServe(cfg.ServerPort, nil))
	} else {
		log.Fatal("TLS configuration is required. " +
			"Set TLS_CERT_FILE and TLS_KEY_FILE environment variables, " +
			"or set TLS_INSECURE=true for local development only.")
	}
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
