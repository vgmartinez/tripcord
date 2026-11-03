# Development tasks for the pre-release tree.
# `build` is CGO_ENABLED=0. `test` uses the race detector, which needs cgo.

BINARY := bin/tripcord
VERSION ?= dev

.PHONY: build test lint fmt test-rule release-gate

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/tripcord

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

fmt:
	gofmt -s -w .

# release-gate fails while a feature a release depends on is missing.
# Today: init --embed wires `tripcord hook`, which this build lacks.
# The pinned-action check passes: both pins reach an action with the
# base input and the embed check.
release-gate:
	TRIPCORD_RELEASE_GATE=1 go test ./cmd/tripcord -run '^TestReleaseGate' -count=1 -v

# test-rule runs one rule's positivos/ and negativos/ fixtures.
#   make test-rule ID=TC-CFG-001
#   make test-rule ID=TEST-CFG-001 RULES_DIR=internal/rules/testdata/packs/fixture
# Without RULES_DIR it searches rules/ and the test fixture pack.
test-rule:
	@test -n "$(ID)" || { echo "usage: make test-rule ID=<rule id> [RULES_DIR=<pack dir>]" >&2; exit 2; }
	TRIPCORD_RULE_ID=$(ID) $(if $(RULES_DIR),TRIPCORD_RULES_DIR=$(abspath $(RULES_DIR))) \
		go test ./internal/rules -run '^TestRuleFixtures$$' -count=1 -v
