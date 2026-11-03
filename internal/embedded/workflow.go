package embedded

import (
	"github.com/vgmartinez/tripcord/internal/project"
)

// WorkflowPin is the commit of this repository whose
// .github/workflows/tripcord-pr.yml the generated workflow calls. It
// must be a full SHA on main; a test checks it names that file.
const WorkflowPin = "6e1d5db7a7d373b7fb4573f554af99471e1d7066"

// checkoutPin is actions/checkout v7.0.1, the version this repository's
// own workflows pin.
const checkoutPin = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"

// ReusableWorkflow is the uses: value of the generated workflow's job,
// without its trailing comment.
const ReusableWorkflow = project.Repository + "/.github/workflows/tripcord-pr.yml@" + WorkflowPin

// Workflow returns .github/workflows/tripcord.yml.
func Workflow() []byte {
	return []byte(`# Written by tripcord init --embed.
# Scans pull requests that touch agent configuration. pull_request only:
# never pull_request_target, so a fork's head never runs with write
# access or secrets.
name: tripcord

on:
  pull_request:
    paths:
      - ".claude/**"
      - ".cursor/**"
      - ".codex/**"
      - ".github/**"
      - ".vscode/**"
      - ".mcp.json"
      - "AGENTS.md"
      - "CLAUDE.md"
      - "GEMINI.md"
      - ".devin/**"
      - ".tripcord/**"

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
setup script run ` + "`" + installCommand + "`" + `. It installs the pinned
Tripcord release, verifies its checksum, and runs ` + "`tripcord scan --config`" + `.
Do not remove or edit the Tripcord hooks in ` + "`.claude/settings.json`" + `,
` + "`.cursor/hooks.json`" + `, or ` + "`.github/hooks/tripcord.json`" + `.
Pull requests are scanned again in CI.
` + agentsEnd + "\n"
}
