SHELL := /bin/sh

BINARY      := privatedns-resolver
CMD         := ./cmd/privatedns-resolver
BACKEND     := privatedns-backend
BACKEND_CMD := ./cmd/privatedns-backend
PORTAL      := privatedns-portal
PORTAL_CMD  := ./cmd/privatedns-portal
ADMIN       := privatedns-admin
ADMIN_CMD   := ./cmd/privatedns-admin
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
DIST        := dist
IMAGE       ?= privatedns

# CGO stays off deliberately: the SQLite driver is pure Go, so every target
# below produces a static binary that runs on any Linux without libraries.
export CGO_ENABLED = 0

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the resolver and backend for the host platform
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)
	go build -ldflags "$(LDFLAGS)" -o $(BACKEND) $(BACKEND_CMD)
	go build -ldflags "$(LDFLAGS)" -o $(PORTAL) $(PORTAL_CMD)
	go build -ldflags "$(LDFLAGS)" -o $(ADMIN) $(ADMIN_CMD)

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
	gofmt -w ./cmd ./resolver ./backend ./portal ./admin

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: fmt-check
fmt-check: ## Fail if any file needs formatting
	@out="$$(gofmt -l ./cmd ./resolver ./backend ./portal ./admin)"; \
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
check: fmt-check vet test scripts-check shell-safety test-install contract-check lego-contract ## Everything CI runs

.PHONY: release
release: ## Cross-compile release binaries into dist/
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 $(CMD)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 $(CMD)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BACKEND)-linux-amd64 $(BACKEND_CMD)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BACKEND)-linux-arm64 $(BACKEND_CMD)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(PORTAL)-linux-amd64 $(PORTAL_CMD)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(PORTAL)-linux-arm64 $(PORTAL_CMD)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(ADMIN)-linux-amd64 $(ADMIN_CMD)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(ADMIN)-linux-arm64 $(ADMIN_CMD)
	@cd $(DIST) && sha256sum $(BINARY)-* > SHA256SUMS
	@ls -lh $(DIST)

.PHONY: clean
clean: ## Remove build output
	rm -rf $(DIST) $(BINARY) $(BINARY).exe $(BACKEND) $(BACKEND).exe $(PORTAL) $(PORTAL).exe $(ADMIN) $(ADMIN).exe coverage.out

.PHONY: version
version: ## Print the version this build would carry
	@echo $(VERSION)

.PHONY: deb
deb: release ## Build .deb packages (needs a Debian or Ubuntu host)
	deploy/debian/build-deb.sh $(VERSION) amd64
	deploy/debian/build-deb.sh $(VERSION) arm64

.PHONY: docker
docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

.PHONY: scripts-check
scripts-check: ## Syntax-check every shipped shell script
	@for f in scripts/install.sh scripts/update.sh scripts/uninstall.sh \
	          scripts/private-dns deploy/scripts/*.sh deploy/debian/build-deb.sh; do \
	  bash -n "$$f" || exit 1; \
	done
	@for f in deploy/debian/postinst deploy/debian/prerm deploy/debian/postrm; do \
	  sh -n "$$f" || exit 1; \
	done
	@echo "shell scripts parse"

.PHONY: checksums
checksums: release ## Regenerate SHA256SUMS over dist/
	@cd $(DIST) && sha256sum privatedns-* > SHA256SUMS && cat SHA256SUMS

.PHONY: contract-check
contract-check: ## Assert the release workflow matches what the installer downloads
	scripts/check-release-contract.sh

.PHONY: shell-safety
shell-safety: ## Catch bugs shellcheck misses (os-release clobbering, unvalidated tags)
	scripts/check-shell-safety.sh

.PHONY: test-install
test-install: ## Run install.sh's preflight against stubbed curl and ss
	scripts/test-install.sh

.PHONY: lego-contract
lego-contract: ## Check issue-cert.sh against a real lego CLI
	DOWNLOAD_LEGO=1 scripts/check-lego-contract.sh
