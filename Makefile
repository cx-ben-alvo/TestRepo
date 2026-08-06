.PHONY: build run clean test fmt vet

# Build the application
build:
	go build -o server cmd/server/main.go

# Run the application
run:
	go run cmd/server/main.go

# Run with custom configuration
run-custom:
	SERVER_PORT=:8080 CLONE_DIR=/tmp/clones DOWNLOAD_DIR=/tmp/downloads go run cmd/server/main.go

# Clean build artifacts
clean:
	rm -f server
	rm -rf /Users/benalvo/clones/*
	rm -rf /Users/benalvo/downloads/*

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Run all checks
check: fmt vet
	@echo "All checks passed!"

# Show project structure
tree:
	@echo "Project structure:"
	@tree -I 'malicious_git_repo|*.md' -L 3

# Show help
help:
	@echo "Available targets:"
	@echo "  make build       - Build the application"
	@echo "  make run         - Run the application"
	@echo "  make run-custom  - Run with custom configuration"
	@echo "  make clean       - Remove build artifacts and downloaded files"
	@echo "  make fmt         - Format Go code"
	@echo "  make vet         - Run go vet"
	@echo "  make check       - Run fmt and vet"
	@echo "  make help        - Show this help message"

