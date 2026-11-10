package embedded

import (
	"github.com/vgmartinez/tripcord/internal/project"
)

// WorkflowPin is the commit of this repository whose
// .github/workflows/tripcord-pr.yml the generated workflow calls. It
// must be a full SHA on main whose tree contains the embed check
// (internal/embedded and rules/TC-CFG-016.yaml), and whose
// tripcord-pr.yml pins the composite action at a commit that has the
// base input and that check. TestPinsHaveEmbedCheck checks the sha.
// TestPinsReachableFromHead requires it to be an ancestor of HEAD. The
// release gate (TestReleaseGatePinsContainLatestScannerChange) fails
// when it does not contain the latest commit on main that changes the
// scanner, the reusable workflows, the action, or the hook manifest.
// TestReleaseGatePinnedActionHasEmbedCheck follows the action pin inside
// the pinned workflow file.
const WorkflowPin = "277066a292b8717d4d91393a10d00c5dd2d51cdb"

// checkoutPin is actions/checkout v7.0.1, the version this repository's
// own workflows pin.
const checkoutPin = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"

// ReusableWorkflow is the uses: value of the generated workflow's job,
// without its trailing comment.
const ReusableWorkflow = project.Repository + "/.github/workflows/tripcord-pr.yml@" + WorkflowPin

// Workflow returns .github/workflows/tripcord.yml.
//
// The workflow sets no paths filter. A filter built from the adapters'
// directory globs would miss files the scan reads: nested copies of
// those directories, CLAUDE.local.md, .cursorrules, .windsurfrules,
// .gemini, .agents, .devcontainer, .opencode, .windsurf, .claude-plugin,
// nested AGENTS.md, and .gitattributes. It would also miss a Claude
// plugin whose manifest names an arbitrary path (claude.ManifestRefs):
// that path is not a fixed glob. Adapters match case-insensitively and
// GitHub's filter does not. A pull request the filter skipped would not
// be scanned.
func Workflow() []byte {
	return []byte(`# Written by tripcord init --embed.
# Scans every pull request. pull_request only: never
# pull_request_target, so a fork's head never runs with write access
# or secrets. There is no paths filter. Agent configuration is not a
# fixed list of paths: adapters read nested files, plugin manifests
# name arbitrary paths, and .gitattributes counts.
name: tripcord

on:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    permissions:
      contents: read # checkout the repository being scanned
      pull-requests: read # tripcord-pr.yml reads pull request reviews
      security-events: write # upload the SARIF report
    # Reusable workflow pinned by full commit SHA (main@` + WorkflowPin[:7] + `).
    uses: ` + ReusableWorkflow + ` # main@` + WorkflowPin[:7] + ` # zizmor: ignore[ref-version-mismatch]
    with:
      fail-on: high
`)
}

// copilotStepName names the step init adds to copilot-setup-steps.yml.
const copilotStepName = "Tripcord bootstrap"

// installCommand runs the bootstrap script in install mode.
const installCommand = bootstrapCommand + " install"

// CopilotSetupSteps returns a new copilot-setup-steps.yml.
func CopilotSetupSteps() []byte {
	return []byte(`# Written by tripcord init --embed.
name: Copilot Setup Steps

on:
  workflow_dispatch:
  push:
    paths:
      - .github/workflows/copilot-setup-steps.yml
  pull_request:
    paths:
      - .github/workflows/copilot-setup-steps.yml

permissions:
  contents: read

concurrency:
  group: copilot-setup-steps-${{ github.ref }}
  cancel-in-progress: true

jobs:
  copilot-setup-steps:
    name: Copilot setup steps
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read # checkout the repository
    steps:
      - name: Checkout
        uses: ` + checkoutPin + `
        with:
          persist-credentials: false
      - name: ` + copilotStepName + `
        run: ` + installCommand + `
`)
}

// copilotStep is the step init adds to copilot-setup-steps.yml.
func copilotStep() *node {
	return object("name", copilotStepName, "run", installCommand)
}

// DevinBlueprint returns a new .devin/blueprint.yaml.
func DevinBlueprint() []byte {
	return []byte(`# Written by tripcord init --embed.
maintenance:
  - name: tripcord
    run: ` + installCommand + `
`)
}

// DefaultPolicy is the .tripcord/policy.yaml init writes: the scan
// defaults from docs/policy.md, written out.
func DefaultPolicy() []byte {
	return []byte(`# Tripcord policy. See docs/policy.md for every field.
version: 1
mode: enforce
fail-on: high
`)
}

// Agents markers delimit the note init adds to AGENTS.md.
const (
	agentsBegin = "<!-- tripcord:begin -->"
	agentsEnd   = "<!-- tripcord:end -->"
)

// agentsNote is the AGENTS.md block, markers included.
func agentsNote() string {
	return agentsBegin + `
## Tripcord

This repository embeds Tripcord (` + "`.tripcord/`" + `). Agents without
repository hooks, such as Codex and Jules, should have their environment
setup script run ` + "`" + installCommand + "`" + `. That command does not
download Tripcord. It checks the pinned build already in the cache and
runs ` + "`tripcord scan --config`" + `. Fill the cache before setup.
Do not remove or edit the Tripcord hooks in ` + "`.claude/settings.json`" + `,
` + "`.cursor/hooks.json`" + `, or ` + "`.github/hooks/tripcord.json`" + `.
Pull requests are scanned again in CI.
` + agentsEnd + "\n"
}
