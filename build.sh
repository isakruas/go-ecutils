#!/bin/bash

PROJECT_NAME="ecutils"
PKG="$PROJECT_NAME"
PKG_LIST=$(go list "${PKG}/..." | grep -v /vendor/)
GO_FILES=$(find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)
BUILDDATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
CODEVERSION="1.1.3"
CODEBUILDREVISION=$(git rev-parse HEAD)
TARGETS=(
    "linux/386"
    "linux/amd64"
    "linux/arm"
    "linux/arm64"
    "windows/386"
    "windows/amd64"
    "darwin/amd64"
)
mkdir -p "dist/$CODEBUILDREVISION"
for target in "${TARGETS[@]}"; do
    IFS='/' read -r -a parts <<< "$target"
    GOOS="${parts[0]}"
    GOARCH="${parts[1]}"
    EXTENSION=""
    if [[ "$GOOS" == "windows" ]]; then
        EXTENSION=".exe"
    fi
    echo "  >  Building binary for $GOOS/$GOARCH..."
    GOOS="$GOOS" GOARCH="$GOARCH" BUILDDATE="$BUILDDATE" CODEBUILDREVISION="$CODEBUILDREVISION" \
        go build -v -ldflags "-X main.GOOS=$GOOS -X main.GOARCH=$GOARCH -X main.CODEVERSION=$CODEVERSION -X main.CODEBUILDDATE=$BUILDDATE -X main.CODEBUILDREVISION=$CODEBUILDREVISION" \
        -o "dist/$CODEBUILDREVISION/${PROJECT_NAME}-${GOOS}-${GOARCH}${EXTENSION}" cmd/main.go
done
