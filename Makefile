# Development tasks for the pre-release tree.
# `build` is CGO_ENABLED=0. `test` uses the race detector, which needs cgo.

BINARY := bin/tripcord
VERSION ?= dev

.PHONY: build test lint fmt

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/tripcord

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

fmt:
	gofmt -s -w .

# test-rule is intentionally not a target yet. See CONTRIBUTING.md.
