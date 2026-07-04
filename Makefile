# Developer workflow for qoltanba. Requires Go 1.25+.
# `make check` is the full pre-commit gate (build + vet + lint + test).
#
# The linter (golangci-lint, config in .golangci.yml) is pinned below and
# installed on demand via `make tools`. It is intentionally NOT tracked as a
# go.mod tool dependency: its transitive graph is huge and would pollute this
# thin service's module. Install once, reuse across builds.

GOLANGCI_VERSION := v2.12.2
GOBIN           := $(shell go env GOPATH)/bin
GOLANGCI        := $(GOBIN)/golangci-lint

.PHONY: build test vet lint fmt tidy check tools openapi openapi-lint check-generated hooks

## build: compile all packages
build:
	go build ./...

## test: run unit tests (no native Kalkan library needed)
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## lint: run golangci-lint (installs the pinned version if missing)
lint: tools
	$(GOLANGCI) run ./...

## fmt: apply formatters (gofmt + goimports) via golangci-lint
fmt: tools
	$(GOLANGCI) fmt ./...

## tidy: prune and sync go.mod/go.sum
tidy:
	go mod tidy

## check: full pre-commit gate
check: build vet lint test

## openapi: regenerate api/openapi.yaml and the Postman collection from the Go types
openapi:
	go run ./tools/openapigen

## openapi-lint: validate the generated OpenAPI spec (needs Node/npx)
openapi-lint:
	npx --yes @redocly/cli@latest lint api/openapi.yaml

## check-generated: fail if the committed OpenAPI/Postman artifacts are stale
check-generated: openapi
	git diff --exit-code api/openapi.yaml deploy/postman/qoltanba.postman_collection.json

## hooks: enable the repo's git hooks (.githooks) for this clone
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks enabled (core.hooksPath=.githooks)"

## tools: install the pinned golangci-lint if absent or outdated
tools:
	@if ! { [ -x "$(GOLANGCI)" ] && "$(GOLANGCI)" version 2>/dev/null | grep -q "$(GOLANGCI_VERSION:v%=%)"; }; then \
		echo "installing golangci-lint $(GOLANGCI_VERSION)"; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION); \
	fi
