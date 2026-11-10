# Development tasks for this tree.
# `build` is CGO_ENABLED=0. `test` uses the race detector, which needs cgo.

BINARY := bin/tripcord
VERSION ?= dev

BENIGN_REPORT ?= bin/benign-report.json
BENIGN_TIMEOUT ?= 35m

.PHONY: build test lint fmt test-rule release-gate wiki benign upstream-check

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BINARY) ./cmd/tripcord

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

fmt:
	gofmt -s -w .

# wiki renders docs/ into bin/wiki, the pages the wiki-sync workflow pushes.
wiki:
	rm -rf bin/wiki
	go run ./cmd/wikigen -out bin/wiki

# benign is opt-in and uses the network. It shallow-fetches every pinned
# commit in corpus/benign/repos.lock, scans it, and writes the report to
# BENIGN_REPORT. It fails on a high finding with no triage.tsv row.
benign: build
	go run ./scripts/benign-scan -tripcord $(BINARY) -out $(BENIGN_REPORT) -timeout $(BENIGN_TIMEOUT)

# upstream-check fails when a URL in schemas/upstream.lock changed.
upstream-check:
	go run ./scripts/upstream-check

# release-gate fails while a feature a release depends on is missing.
# It checks that this build has the `tripcord hook` the init --embed
# wiring runs, that both pinned actions have the base input and the
# embed check, and that every documented pin contains the latest scanner
# change on main. Run it before tagging; no CI workflow runs it.
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
