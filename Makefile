SHELL := /bin/sh

BINARY      := privatedns-resolver
CMD         := ./cmd/privatedns-resolver
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
DIST        := dist

# CGO stays off deliberately: the SQLite driver is pure Go, so every target
# below produces a static binary that runs on any Linux without libraries.
export CGO_ENABLED = 0

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the resolver for the host platform
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

.PHONY: test
test: ## Run the full test suite
	go test ./...

.PHONY: test-race
test-race: ## Run tests with the race detector
	CGO_ENABLED=1 go test -race ./...

.PHONY: cover
cover: ## Run tests and report coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt: ## Format all Go source
	gofmt -w ./cmd ./resolver

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt-check
fmt-check: ## Fail if any file needs formatting
	@out="$$(gofmt -l ./cmd ./resolver)"; \
	if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi
	@echo "gofmt clean"

.PHONY: fuzz
fuzz: ## Run fuzz targets briefly (FUZZTIME=30s make fuzz)
	go test -run "^$$" -fuzz FuzzUnpackAndResolve -fuzztime $(or $(FUZZTIME),30s) ./resolver
	go test -run "^$$" -fuzz FuzzRouteIDFromSNI  -fuzztime $(or $(FUZZTIME),30s) ./resolver

.PHONY: vuln
vuln: ## Check dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: check
check: fmt-check vet test ## Everything CI runs

.PHONY: release
release: ## Cross-compile release binaries into dist/
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 $(CMD)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 $(CMD)
	@cd $(DIST) && sha256sum $(BINARY)-* > SHA256SUMS
	@ls -lh $(DIST)

.PHONY: docker
docker: ## Build the container image
	docker build -t privatedns:$(VERSION) .

.PHONY: clean
clean: ## Remove build output
	rm -rf $(DIST) $(BINARY) $(BINARY).exe coverage.out

.PHONY: version
version: ## Print the version this build would carry
	@echo $(VERSION)
