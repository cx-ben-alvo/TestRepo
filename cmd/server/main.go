package main

import (
	"fmt"
	"log"
	http2 "net/http"
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

	// Register routes wrapped with the security-headers middleware so that
	// every response carries a Content-Security-Policy and related headers.
	http2.Handle("/api/repo/create", handler.SecurityHeaders(http2.HandlerFunc(h.CreateRepo)))
	http2.Handle("/api/repo/clone", handler.SecurityHeaders(http2.HandlerFunc(h.CloneRepo)))
	http2.Handle("/api/repo/list", handler.SecurityHeaders(http2.HandlerFunc(h.ListRepos)))

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// TLS is mandatory. Both TLS_CERT_FILE and TLS_KEY_FILE must be set.
	// Plain-text HTTP is not supported to prevent exposure to
	// Man-in-the-Middle attacks (CWE-319).
	if !cfg.TLSEnabled() {
		log.Fatal("TLS is required: set TLS_CERT_FILE and TLS_KEY_FILE environment variables")
	}
	fmt.Println("TLS enabled: serving over HTTPS")
	log.Fatal(http2.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
