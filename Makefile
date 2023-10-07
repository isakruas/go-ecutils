# Variable Definitions
PROJECT_NAME := "ecutils"
PKG := "$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)
GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)
BUILDDATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
CODEVERSION := "1.0.0"
CODEBUILDREVISION := $(shell git rev-parse HEAD)
.PHONY: all dep build clean test coverage zip lint

all: build

# Building Project
build: dep
	@echo "  >  Building binary for $(GOOS)/$(GOARCH)..."
	GOARCH=$(GOARCH) GOOS=$(GOOS) BUILDDATE=$(BUILDDATE) CODEBUILDREVISION=$(CODEBUILDREVISION) go build -v -ldflags "-X main.GOOS=$(GOOS) -X main.GOARCH=$(GOARCH) -X main.CODEVERSION=$(CODEVERSION) -X main.CODEBUILDDATE=$(BUILDDATE) -X main.CODEBUILDREVISION=$(CODEBUILDREVISION)" $(PKG)
	@./scripts/test_ecutils.sh;
	@mv ${PROJECT_NAME} "${PROJECT_NAME}-${GOOS}-${GOARCH}"

test: dep
	@echo "  >  Running tests..."
	@go test -v -race ./...

coverage: ## Generate global code coverage report
	@echo "  >  Generating code coverage report..."
	@./scripts/coverage.sh;

lint: ## Lint the files
	@echo "  >  Linting source code..."
	@./scripts/lint.sh $(LINTERS)

dep: ## Get the dependencies
	@echo "  >  Getting dependencies..."
	@go mod download

clean: ## Remove previous build
	@echo "  >  Cleaning up previous build..."
	@-rm ${PROJECT_NAME} 2> /dev/null || true

arch:
	@echo "  >  Displaying system architecture information..."
	@go env GOARCH GOOS

zip:
	rm -rf ecutils.zip
	zip -r ecutils.zip ec ecdh ecdsa eck ecmo go.mod go.sum LICENSE main.go Makefile README.md scripts
	chmod 444 ecutils.zip
