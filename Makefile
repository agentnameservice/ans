.PHONY: build build-ra build-tl build-verify build-dns \
       test test-cover test-race lint vet fmt \
       run-local run-ra run-tl \
       clean generate check docs-sync \
       docker-build docker-compose-up docker-compose-down docker-compose-bootstrap

# $(GOLANGCI_LINT) is intentionally NOT in .PHONY — it's a real file
# target whose presence skips the install step on subsequent runs.

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  = -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

GOBIN   = ./bin
GOFLAGS = -trimpath

# Coverage threshold
COVERAGE_THRESHOLD = 90

# Pinned tool versions. The golangci-lint version must match the
# `version:` value in .github/workflows/ci.yml — drift here is what
# caused PR-time lint failures that didn't surface in local `make
# check`. Bump both at once.
GOLANGCI_LINT_VERSION = v2.11.4
GOLANGCI_LINT         = $(GOBIN)/golangci-lint

# ─── Build ──────────────────────────────────────────────────────────

build: docs-sync build-ra build-tl build-verify build-dns

build-ra: docs-sync
	@echo "Building ans-ra..."
	@go build $(GOFLAGS) $(LDFLAGS) -o $(GOBIN)/ans-ra ./cmd/ans-ra

build-tl: docs-sync
	@echo "Building ans-tl..."
	@go build $(GOFLAGS) $(LDFLAGS) -o $(GOBIN)/ans-tl ./cmd/ans-tl

build-verify:
	@echo "Building ans-verify..."
	@go build $(GOFLAGS) $(LDFLAGS) -o $(GOBIN)/ans-verify ./cmd/ans-verify

build-dns:
	@echo "Building ans-dns..."
	@go build $(GOFLAGS) $(LDFLAGS) -o $(GOBIN)/ans-dns ./cmd/ans-dns

# docs-sync copies the canonical OpenAPI specs into the docsui
# adapter's //go:embed directory. Running before every build keeps
# the Swagger-UI-served spec in lockstep with spec/. A test in
# internal/adapter/docsui/ also asserts byte-equality so a drifted
# pair blocks `make test` rather than silently ship.
docs-sync:
	@cp spec/api-spec-v2.yaml internal/adapter/docsui/openapi/ra.yaml
	@cp spec/api-spec-tl-v2.yaml internal/adapter/docsui/openapi/tl.yaml

# ─── Test ───────────────────────────────────────────────────────────

test:
	@echo "Running tests..."
	@go test ./... -count=1

test-cover:
	@echo "Running tests with coverage..."
	@# Exclude cmd/* from the instrumented set. The four command
	@# binaries (ans-ra, ans-tl, ans-verify, ans-dns) are thin glue:
	@# flag parsing, config loading, dependency wiring, then hand off
	@# to library code under internal/. We don't write unit tests for
	@# main() — counting those ~30 unexercised statements toward the
	@# 90% gate would only penalize real logic coverage. The library
	@# packages under internal/ are where the gate has teeth.
	@#
	@# Exclude acmetest for the same reason: it is a test double (an
	@# in-process fake RFC 8555 server) imported only by _test.go
	@# files and never compiled into a production binary. Its fault-
	@# injection knobs are exercised selectively per test, so counting
	@# its unused branches as "production" statements would penalize
	@# real coverage exactly the way main() would. Test scaffolding is
	@# not the system under test.
	@pkgs=$$(go list ./... | grep -v -e '/cmd/' -e '/acmetest' | tr '\n' ',' | sed 's/,$$//'); \
	go test ./... -count=1 -coverpkg=$$pkgs -coverprofile=coverage.out -covermode=atomic
	@go tool cover -func=coverage.out
	@echo ""
	@echo "Checking coverage threshold ($(COVERAGE_THRESHOLD)%)..."
	@total=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%'); \
	if [ "$$(echo "$$total < $(COVERAGE_THRESHOLD)" | bc -l)" = "1" ]; then \
		echo "FAIL: Coverage $$total% is below $(COVERAGE_THRESHOLD)% threshold"; \
		exit 1; \
	else \
		echo "OK: Coverage $$total% meets $(COVERAGE_THRESHOLD)% threshold"; \
	fi

test-race:
	@echo "Running tests with race detector..."
	@go test ./... -count=1 -race

# ─── Quality ────────────────────────────────────────────────────────

# Auto-install the pinned golangci-lint into $(GOBIN) on first run.
# Make's file-target rule re-uses the binary on subsequent runs; bump
# GOLANGCI_LINT_VERSION above to refresh.
$(GOLANGCI_LINT):
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) into $(GOBIN)..."
	@GOBIN=$(abspath $(GOBIN)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	@echo "Running linter ($(GOLANGCI_LINT_VERSION))..."
	@$(GOLANGCI_LINT) run ./...

vet:
	@echo "Running go vet..."
	@go vet ./...

fmt:
	@echo "Checking formatting..."
	@# Restrict to this module's tracked Go files. `gofmt -l .` would
	@# also traverse any sibling directories under this tree (separate
	@# go.mods, git-ignored clones) and fail on their formatting which
	@# is not our concern.
	@files=$$(git ls-files '*.go' 2>/dev/null); \
	if [ -z "$$files" ]; then \
		echo "no tracked Go files found"; \
		exit 0; \
	fi; \
	bad=$$(echo "$$files" | xargs gofmt -l); \
	if [ -n "$$bad" ]; then \
		echo "unformatted files:"; \
		echo "$$bad"; \
		exit 1; \
	fi

check: fmt vet lint test-cover
	@echo "All checks passed."

# ─── Run ────────────────────────────────────────────────────────────

run-local: build
	@echo "Starting ans-tl on :18081..."
	@$(GOBIN)/ans-tl --config config/tl-local.yaml &
	@sleep 1
	@echo "Starting ans-ra on :18080..."
	@$(GOBIN)/ans-ra --config config/ra-local.yaml

run-ra: build-ra
	@$(GOBIN)/ans-ra --config config/ra-local.yaml

run-tl: build-tl
	@$(GOBIN)/ans-tl --config config/tl-local.yaml

# ─── Generate ───────────────────────────────────────────────────────

generate:
	@echo "Running go generate..."
	@go generate ./...

# ─── Docker ─────────────────────────────────────────────────────────

docker-build:
	@echo "Building Docker images..."
	@docker build -f Dockerfile.ans-ra     --build-arg VERSION=$(VERSION) -t ans-ra:$(VERSION) -t ans-ra:latest .
	@docker build -f Dockerfile.ans-tl     --build-arg VERSION=$(VERSION) -t ans-tl:$(VERSION) -t ans-tl:latest .
	@docker build -f Dockerfile.ans-verify --build-arg VERSION=$(VERSION) -t ans-verify:$(VERSION) -t ans-verify:latest .

docker-compose-up:
	@docker compose up --build -d

docker-compose-down:
	@docker compose down

# Bootstrap the TL's producerKeys trust list with the RA signer's
# pubkey after `docker compose up`. The TL ships with empty trust
# (config/tl-docker.yaml) and rejects events until at least one
# producer is registered. Idempotent — re-runs are safe.
docker-compose-bootstrap:
	@./scripts/docker-compose-bootstrap.sh

# ─── Clean ──────────────────────────────────────────────────────────

clean:
	@rm -rf $(GOBIN) coverage.out coverage.html data/
	@echo "Cleaned."
