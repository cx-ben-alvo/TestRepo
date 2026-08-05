package main

import (
	"fmt"
	"log"
	http9 "net/http"
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

	// Register routes — each handler is wrapped with SecurityHeaders so that
	// every response carries the Content-Security-Policy and related headers
	// (CWE-346 / Missing Content Security Policy remediation).
	http9.Handle("/api/repo/create", handler.SecurityHeaders(http9.HandlerFunc(h.CreateRepo)))
	http9.Handle("/api/repo/clone", handler.SecurityHeaders(http9.HandlerFunc(h.CloneRepo)))
	http9.Handle("/api/repo/list", handler.SecurityHeaders(http9.HandlerFunc(h.ListRepos)))

	// Start server
	fmt.Printf("Server starting on %s\n", cfg.ServerPort)
	fmt.Println("")
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/repo/create - Create repo")
	fmt.Println("  POST /api/repo/clone - Clone Git repo")
	fmt.Println("  POST /api/repo/fetch - Fetch resource")
	fmt.Println("  GET  /api/repo/list - List all repos")
	fmt.Println("")

	// TLS certificate and key paths must be provided via TLS_CERT_FILE and
	// TLS_KEY_FILE environment variables. Using ListenAndServeTLS ensures all
	// traffic is encrypted in transit (CWE-319 / OWASP A02:2021).
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE environment variables must be set")
	}
	log.Fatal(http9.ListenAndServeTLS(cfg.ServerPort, cfg.TLSCertFile, cfg.TLSKeyFile, nil))
}

func initDirs(cfg *config.Config) {
	os.MkdirAll(cfg.CloneDir, 0755)
	os.MkdirAll(cfg.DownloadDir, 0755)
}
