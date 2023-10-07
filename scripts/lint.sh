#!/usr/bin/env bash

if ! [ -x "$(command -v golint)" ]; then
  echo 'Error: golangci-lint is not installed.' >&2
  exit 1
fi

exec golint ./...
