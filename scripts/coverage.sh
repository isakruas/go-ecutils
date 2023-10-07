#!/usr/bin/env bash

set -e

# Directory for HTML coverage reports
COVERAGE_DIR="./coverage"

# Clean the existing coverage directory, if it exists
rm -rf "$COVERAGE_DIR"
mkdir -p "$COVERAGE_DIR"

# Run tests and generate consolidated coverage report, excluding the "vendor" directory
go test -race -coverprofile="$COVERAGE_DIR/coverage.out" -covermode=atomic $(go list ./... | grep -v "/vendor/")

# Generate HTML report from the consolidated coverage profile file
go tool cover -html="$COVERAGE_DIR/coverage.out" -o "$COVERAGE_DIR/coverage.html"

echo "Coverage report generated in $COVERAGE_DIR/coverage.html"
