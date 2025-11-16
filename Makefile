.PHONY: build run test clean docker-build docker-run install dev generate-password help

# Binary name
BINARY=registry
CMD_DIR=./cmd/registry

# Build variables
VERSION?=dev
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-w -s -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	@echo "Building $(BINARY)..."
	go build $(LDFLAGS) -o $(BINARY) $(CMD_DIR)
	@echo "Build complete: $(BINARY)"

build-linux: ## Build Linux binary
	@echo "Building $(BINARY) for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux $(CMD_DIR)
	@echo "Build complete: $(BINARY)-linux"

install: ## Install the binary to $GOPATH/bin
	@echo "Installing $(BINARY)..."
	go install $(LDFLAGS) $(CMD_DIR)

run: ## Run the application
	@if [ ! -f config.yaml ]; then \
		echo "Creating config.yaml from example..."; \
		cp config.example.yaml config.yaml; \
	fi
	go run $(CMD_DIR) --config config.yaml

dev: ## Run in development mode with auto-reload (requires air)
	air

test: ## Run tests
	go test -v -race -cover ./...

test-coverage: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -f $(BINARY) $(BINARY)-linux
	rm -f coverage.out coverage.html
	rm -rf data/
	@echo "Clean complete"

docker-build: ## Build Docker image
	docker build -t registry:$(VERSION) .

docker-run: ## Run Docker container
	@if [ ! -f config.yaml ]; then \
		echo "Creating config.yaml from example..."; \
		cp config.example.yaml config.yaml; \
	fi
	docker-compose up

docker-stop: ## Stop Docker containers
	docker-compose down

docker-clean: ## Clean Docker containers and volumes
	docker-compose down -v

generate-password: ## Generate bcrypt password hash (usage: make generate-password PASSWORD=yourpassword)
	@if [ -z "$(PASSWORD)" ]; then \
		echo "Usage: make generate-password PASSWORD=yourpassword"; \
		exit 1; \
	fi
	@echo "$(PASSWORD)" | htpasswd -niBC 10 user | cut -d: -f2

fmt: ## Format code
	go fmt ./...
	gofmt -s -w .

lint: ## Run linter
	golangci-lint run

tidy: ## Tidy go modules
	go mod tidy

verify: fmt lint test ## Run fmt, lint, and test

.DEFAULT_GOAL := help
