# TC-CFG-016 version skew: an older scanner judging a newer embed

Status: approved, with the conditions in section 0. The fix (the first of
three changes, section 5 "Rollout order") implements it. The spike's
throwaway workflows and action stay on their own branch and never reach
main; section 2 records what they showed.

## 0. Approved conditions

These bind the implementation; where an earlier section says otherwise,
this section wins.

1. **Narrow exception.** An unknown pin in a trusted scan drops from high
   only when all three hold: the scanner is a release build; embed.json's
   `version` is strictly greater than the scanner's; `tripcord.yml`
   matches its recorded digest. Even then every semantic invariant (`H1`,
   `H2`, `W4`, `B4`, `S1`, `G1`, `M1`, ...) and removal relative to the
   base still report high. Positive `embed-inflated-version-hook-loosened`
   (embed.json version 99.0.0 plus `onFailure: continue`) stays high.
2. **Pin changes.** A pin change relative to the base is always
   `repinned`, high, even when it equals `--executing-workflow`.
   `--executing-workflow` only accepts a pin the base also has: fork SHAs
   are reachable from the parent repository, and under `pull_request` the
   pull request's own `tripcord.yml` picks the workflow that runs, so the
   flag attests only to itself. `base-repinned` stays high.
3. **Writer witness.** A known pin with an unknown render is `changed`,
   high. `TestTemplateChangeNeedsRepin` enforces "a template change needs
   a new `WorkflowPin`" on every pull request (`go test ./...` in CI), not
   only in the release gate.
4. **`KnownWorkflowPins`** is append-only, starts empty, is guarded by the
   release gate (`TestReleaseGateKnownWorkflowPins`), and never holds
   `8b33b1b` or `6e1d5db`.
5. **`init`** on a release build rejects a `--version` older than itself.
6. **Fixtures.** No existing fixture, `expect.yaml` entry, golden,
   `mutations.golden`, corpus file, `corpus_malicious_test.go`, or
   `allowlist.tsv` line changes; additions only. The end-to-end
   `TestVersionSkewCIScanner` reproduces the six highs.
7. **Out of v0.** `ref: ${{ job.workflow_sha }}` and the published-binary
   option (section 7) are recorded in `docs/release-notes.md` as a known
   gap and future options only. Distribution is not decided here.

`TestVersionSkewCIScanner` never skips. It runs only under the release
gate (`TRIPCORD_RELEASE_GATE=1`, `make release-gate`), and there it fails
with the six highs until the action repin and the `WorkflowPin` repin
land, so no tag ships before them. Without the gate it logs why and
passes. A synthetic unit test (`cmd/tripcord/version_skew_test.go`)
covers the fix itself: a simulated older scanner reports no high on a
newer embed, and every security mutation, the inflated version included,
reports high. Moving the end-to-end test into per-pull-request CI,
passing, is the third change.

### Implementation notes

- **Severity.** Tripcord has no `info` severity (`low`, `medium`,
  `high`, `critical`). Every "info" below is implemented as **low**, with
  the `unverified` state.
- **Exit code.** Sections 3.4 and 6 say a malformed `--executing-workflow`
  "exits 2". `scan` never returns 2 (it is the hook-block code, see
  `docs/commands.md`), and every configuration error exits 3, so a
  malformed value, and an older `init --version`, exit 3.
- **`stale`** is no longer reported; its rule clause is replaced by
  one low clause for `outdated` and `unverified`. The forged-digest
  positive is now `changed` through `B4` (or the writer witness), still
  high.
- **Main repinned first.** While this change was in review, main moved
  `WorkflowPin` from `6a12795` to `277066a` (still action `8b33b1b`) and
  dropped the workflow's `paths` filter. `known_renders.json` therefore
  holds only `277066a`. With `KnownWorkflowPins` empty (condition 4), no
  pin and no render can be `outdated` today, so no rule fixture can
  hold that state. `outdated` shares the `unverified` clause, which
  `embed-manifest-future-schema` pins, and
  `TestVersionSkewKnownPinIsOutdatedLow` checks it end to end. Until
  the `WorkflowPin` repin appends `6a12795` and `277066a`, a trusted
  scan reports embeds under either as `pin-unknown`, high. W2 still
  applies only to a `paths` filter that is present. Since main stopped
  writing `copilot-setup-steps.yml` without `--cloud-setup`, the
  scanner at `8b33b1b` also reports it missing, so
  `TestVersionSkewCIScanner` now fails with seven highs, not six.
  Section 1 and later describe the tree at `1571edc`.
- **Files.** `internal/embedded/pins.go` (pins, `WorkflowRef`, version
  order), `invariants.go`, `renders.go` and the generated
  `known_renders.json` (`go run ./scripts/knownrenders`), plus the
  classification in `check.go`.
- **Workflow template.** The `tripcord.yml` render digest replaces every
  `uses:` value and the `main@<short>` comment, and the pin check judges
  every job's `uses:` on its own. A `uses:` that is not this
  repository's `tripcord-pr.yml` at a full SHA is `pin-malformed`, and
  a workflow with no `uses:` at all is too.
- **New positives** are config-item JSON fixtures, one per new
  `severity_when` clause, so `TestSeverityClausesAreCovered` pins each
  of them: `embed-inflated-version-hook-loosened`, `embed-pin-unknown`,
  `embed-pin-malformed`, and `embed-manifest-future-schema` (low). A raw archive would carry
  `bootstrap.sh`, whose shebang needs an `allowlist.tsv` line, and that
  list only shrinks.
- **CI context** is plain `scan` with `--executing-workflow` or
  `GITHUB_ACTIONS=true`. A `--staged` scan and `preopen` are always
  trusted.
- **The action** passes `--executing-workflow` only when it builds its
  own source (no `binary` or `ref` input), `job.workflow_repository` is
  `github.action_repository` and `vgmartinez/tripcord`, and
  `job.workflow_file_path` is `.github/workflows/tripcord-pr.yml`.

## 1. Problem

Here is what runs when a user's pull request is scanned:

1. The embed's `tripcord.yml` calls `tripcord-pr.yml@W`, where
   `W = embedded.WorkflowPin` (today `6a12795`).
2. Line 111 of `tripcord-pr.yml@W` calls `.github/actions/tripcord@A`
   (today `A = 8b33b1b`).
3. The action runs `CGO_ENABLED=0 go build -trimpath ./cmd/tripcord` from
   `github.action_path`. That directory is A's tree, delivered as a
   tarball with no `.git`.

So the CI scanner is always A's code. The embed was written by `init` at
some commit H. H is newer than W, because a commit cannot pin itself, and W
is newer than A for the same reason. **The CI scanner is therefore always
older than the code that wrote the embed it checks**, and it cannot know W.

`ownFile` and `compare` (`internal/embedded/check.go` ~510-616), and
`entryState` (~652-668), assume the running scanner is the newest Tripcord:

- `want` is this scanner's own render.
- `recorded` is the digest embed.json records, written by the newer `init`.
- `got == recorded && got != want` is reported as `stale`: HIGH, "written by
  an older Tripcord".

A newer writer always lands in that branch on every surface whose template
changed between A and H.

### Reproduction (local, this branch)

The embed was made with `init --embed` from main `2ccafcc`. The scanner was
built the way the action builds it: `git archive 8b33b1b`, then
`CGO_ENABLED=0 go build -trimpath ./cmd/tripcord`.

```text
$ tripcord-A scan . --format text
HIGH TC-CFG-016 .claude/settings.json: Tripcord guard was written by an older Tripcord ...   (PreToolUse)
HIGH TC-CFG-016 .claude/settings.json: Tripcord guard was written by an older Tripcord ...   (SessionStart)
HIGH TC-CFG-016 .github/hooks/tripcord.json: Tripcord guard was written by an older Tripcord ... (preToolUse)
HIGH TC-CFG-016 .cursor/hooks.json: Tripcord guard was written by an older Tripcord ...      (preToolUse)
HIGH TC-CFG-016 .github/workflows/tripcord.yml: Tripcord guard was written by an older Tripcord ...
HIGH TC-CFG-016 .tripcord/bootstrap.sh: Tripcord guard was written by an older Tripcord ...
6 finding(s): 0 critical, 6 high, 0 medium, 0 low; 0 warning(s)

$ tripcord-2ccafcc scan . --format text
0 finding(s): 0 critical, 0 high, 0 medium, 0 low; 0 warning(s)
```

The same skew appears even between two commits that share a pin. A
`2ccafcc` scanner reports `bootstrap.sh` as stale on every committed
TC-CFG-016 embed negative (`embed-fresh`, `embed-claude-only`,
`embed-crlf-checkout`), which current `init` (`3f322e4`) wrote, because
#116 changed the bootstrap template. Both commits have `WorkflowPin`
`6a12795`.

### What must not be lost

The forged-digest positive (`embed-bootstrap-digest-forged`) is caught
today **only** by the `stale` state: the edited file equals the forged
recorded digest. Simply downgrading `stale` would therefore silently drop
that positive. Whatever replaces `stale` needs a check that does not depend
on the scanner's version (section 3).

### Other places with the same flaw (latent, not hit by the repro)

- The Copilot setup step.
- The `.gitattributes` target list.
- The manifest `schema` string. A newer `tripcord.embed/v2` would be
  reported `unreadable`, which is HIGH.
- The harness list.
- The set of hook events. If a newer writer drops an event, the older
  scanner reports `missing`, which is HIGH.
- `bootstrap.sh install` and `session-start` run `scan --config` with the
  *pinned release* binary. When `init` is newer than `--version`, that scan
  is an older scanner judging a newer embed too.

## 2. Spike: can a reusable workflow read the SHA it runs at?

### Docs (docs.github.com)

- [Contexts reference, `job` context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context):
  - `job.workflow_ref`: "The full ref of the workflow file that defines
    the current job. [...] For jobs defined directly in a workflow file,
    this is the same as `github.workflow_ref`. For jobs defined in a Reuse
    workflows, this refers to the reusable workflow file. (not available on
    GitHub Enterprise Server)"
  - `job.workflow_sha`: "The commit SHA of the workflow file that defines
    the current job. (not available on GitHub Enterprise Server)"
  - `job.workflow_repository` and `job.workflow_file_path` are described
    the same way.
  - The page's example states the intended use: "This example reusable
    workflow uses `job.workflow_repository` and `job.workflow_sha` to check
    out its own source code, rather than the caller's repository."
  - The availability table lists `job` for `jobs.<job_id>.steps.with`, so
    the value can be passed to the action as a step input.
- [Contexts reference, `github` context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context):
  - `github.workflow_ref`: "The ref path to the workflow."
  - `github.workflow_sha`: "The commit SHA for the workflow file."
- [Reusing workflow configurations, `github` context](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#github-context):
  "When a reusable workflow is triggered by a caller workflow, the `github`
  context is always associated with the caller workflow." So
  `github.workflow_sha` and `github.workflow_ref` describe the **caller**.
- [OpenID Connect reference, custom claims](https://docs.github.com/en/actions/reference/security/oidc#custom-claims-provided-by-github):
  - `job_workflow_ref`: "For jobs using a reusable workflow, the ref path
    to the reusable workflow."
  - `job_workflow_sha`: "For jobs using a reusable workflow, the commit SHA
    for the reusable workflow file."
- [OIDC with reusable workflows](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows):
  "The `workflow`, `ref`, and other attributes describe the caller
  workflow, while `job_workflow_ref` refers to the called workflow."
- `github.job_workflow_sha` is not documented anywhere. It is not a
  context property.

### Real run

The run is <https://github.com/vgmartinez/tripcord/actions/runs/42804705651>
(event `pull_request`, PR #117). It was built as a three-level chain shaped
like production, where each level is pinned by full SHA:

| Level | File | Pinned SHA |
|---|---|---|
| caller (PR head) | `.github/workflows/spike-tc-cfg-016-caller.yml` | head `ccd46c0`, merge ref `702e985` |
| called reusable workflow | `.github/workflows/spike-tc-cfg-016-called.yml` | `959a98854a23350de2fc6ad8d66fe1308d13b3f1` |
| composite action, used by the called workflow | `.github/actions/spike-tc-cfg-016/action.yml` | `27fdfbe3ad5952b16dddadc91aaabdf818e96a6b` |

Only the called job requested `id-token: write`, and the caller granted it.
Only the two `job_workflow_*` claims were decoded, and the token was masked
and never printed.

Exact output of the called job, "called / Echo identity":

```text
--- job context (workflow identity fields) ---
{
  "workflow_file_path": ".github/workflows/spike-tc-cfg-016-called.yml",
  "workflow_ref": "vgmartinez/tripcord/.github/workflows/spike-tc-cfg-016-called.yml@959a98854a23350de2fc6ad8d66fe1308d13b3f1",
  "workflow_repository": "vgmartinez/tripcord",
  "workflow_sha": "959a98854a23350de2fc6ad8d66fe1308d13b3f1"
}
--- github context (workflow/sha/ref fields; token excluded) ---
{
  "base_ref": "main",
  "event_name": "pull_request",
  "head_ref": "cursor/tc-cfg-016-version-skew-spike-d737",
  "job_workflow_ref": null,
  "job_workflow_sha": null,
  "pr_head_sha": "ccd46c0853180d21c851a6c4d5320880761a33d6",
  "ref": "refs/pull/117/merge",
  "repository": "vgmartinez/tripcord",
  "sha": "702e98537ea6071d2b74396203acd3480da48161",
  "workflow": "spike-tc-cfg-016-caller",
  "workflow_ref": "vgmartinez/tripcord/.github/workflows/spike-tc-cfg-016-caller.yml@refs/pull/117/merge",
  "workflow_sha": "702e98537ea6071d2b74396203acd3480da48161"
}
--- runner env ---
GITHUB_WORKFLOW_SHA=702e98537ea6071d2b74396203acd3480da48161
GITHUB_WORKFLOW_REF=vgmartinez/tripcord/.github/workflows/spike-tc-cfg-016-caller.yml@refs/pull/117/merge
GITHUB_SHA=702e98537ea6071d2b74396203acd3480da48161
GITHUB_REF=refs/pull/117/merge
{
  "job_workflow_ref": "vgmartinez/tripcord/.github/workflows/spike-tc-cfg-016-called.yml@959a98854a23350de2fc6ad8d66fe1308d13b3f1",
  "job_workflow_sha": "959a98854a23350de2fc6ad8d66fe1308d13b3f1"
}
--- composite: job context ---
{
  "workflow_file_path": ".github/workflows/spike-tc-cfg-016-called.yml",
  "workflow_ref": "vgmartinez/tripcord/.github/workflows/spike-tc-cfg-016-called.yml@959a98854a23350de2fc6ad8d66fe1308d13b3f1",
  "workflow_repository": "vgmartinez/tripcord",
  "workflow_sha": "959a98854a23350de2fc6ad8d66fe1308d13b3f1"
}
--- composite: github.action_* ---
github.action_ref=27fdfbe3ad5952b16dddadc91aaabdf818e96a6b
github.action_repository=vgmartinez/tripcord
env GITHUB_WORKFLOW_SHA=702e98537ea6071d2b74396203acd3480da48161
env GITHUB_WORKFLOW_REF=vgmartinez/tripcord/.github/workflows/spike-tc-cfg-016-caller.yml@refs/pull/117/merge
```

Which value is which:

| Candidate | Value seen | Equals |
|---|---|---|
| `job.workflow_sha`, in the workflow and inside the composite action | `959a988` | **called workflow** |
| `job.workflow_ref` | `...called.yml@959a988` | **called workflow** |
| OIDC `job_workflow_sha` | `959a988` | **called workflow** |
| OIDC `job_workflow_ref` | `...called.yml@959a988` | **called workflow** |
| `github.workflow_sha`, `GITHUB_WORKFLOW_SHA` | `702e985` | caller (the PR merge commit, not even the head `ccd46c0`) |
| `github.workflow_ref`, `GITHUB_WORKFLOW_REF` | `...caller.yml@refs/pull/117/merge` | caller |
| `github.sha` | `702e985` | caller's merge commit |
| `github.job_workflow_sha`, `github.job_workflow_ref` | `null` | does not exist |
| `github.action_ref` | `27fdfbe` | the composite action (A), not the workflow |

**Conclusion.** `job.workflow_sha` is a documented and observed source for
the SHA the called workflow runs at. Inside the composite action it still
names the reusable workflow. It needs no extra permission, unlike the OIDC
claim, which needs `id-token: write`.

Limits of the spike:

- It covers github.com only: the `job.workflow_*` properties are not
  available on GHES.
- The caller used a full SHA. Calls by branch or tag were not exercised,
  and the design rejects those pins anyway.
- Caller and callee were in the same repository.

Even so, the value is **self-attestation**. It is reported to the job that
is running, and if W is fork code, the scanner reading it is fork code too
(section 5).

## 3. Design

### 3.1 Principles

1. **Version-independent checks decide HIGH.** These are checks whose
   answer does not depend on which Tripcord wrote the embed:
   - semantic invariants (section 3.2);
   - consistency with the manifest the writer produced;
   - base-relative changes.
2. **Version-dependent checks never produce HIGH for an unknown, possibly
   newer render.** These are exact-render comparisons against this
   scanner's templates.
3. **Unverifiable results degrade, never vanish.** They become `info` (or
   `low` for a known older render or pin), with a message telling the user
   to scan locally with the latest Tripcord.

### 3.2 Semantic invariants: a contract every Tripcord version keeps

The invariants live in `internal/embedded/invariants.go`. Each one has a
stable id. **An invariant may be tightened in a later version but never
loosened.** A test pins that rule: `TestInvariantsHoldForInit` checks that
current `init` output satisfies every invariant, and the invariant table is
append-only (checked against `origin/main` like `KnownWorkflowPins`).
Loosening one would make older scanners flag newer embeds, which is exactly
this bug, so it is a breaking change.

| Id | Surface | Invariant |
|---|---|---|
| `B1` | `bootstrap.sh` | Line 1 is `#!/bin/sh`, and `set -eu` comes before any other command. |
| `B2` | `bootstrap.sh` | Exactly one `TRIPCORD_VERSION='<embed.json version>'`. |
| `B3` | `bootstrap.sh` | For each platform in embed.json `sha256`, exactly one arm `<platform>) printf '%s\n' '<sum>' ;;`, and no other 64-hex literal. |
| `B4` | `bootstrap.sh` | The checksum gate `if [ "$got" != "$want" ]; then` is present and its next line starts with `fail `. |
| `H1` | each wired hook harness | The pre-tool event holds an entry that runs `.tripcord/bootstrap.sh` with `hook` (`runsGuard`). |
| `H2` | Claude `PreToolUse` | That entry's `matcher` is `*`, and its command hook has `"onFailure": "block"`. |
| `H3` | Cursor `preToolUse` | `"failClosed": true`, with no `matcher` that narrows it. |
| `H4` | Copilot `preToolUse` | `type: command`, `cwd: "."`, `timeoutSec` >= 60. A timed-out Copilot hook fails open. |
| `H5` | all hook harnesses | The guard command passes `--on-failure block`. |
| `H6` | all hook harnesses | No `disableAllHooks: true` in the shared file. This is the existing disable-all clause. |
| `W1` | `tripcord.yml` | `on` contains `pull_request` and none of `pull_request_target` or `workflow_run`. |
| `W2` | `tripcord.yml` | `on.pull_request.paths`, when set, is a superset of `.tripcord/**`, `.claude/**`, `.cursor/**`, `.github/**`. The set only grows. |
| `W3` | `tripcord.yml` | Exactly one job uses this repository's `tripcord-pr.yml` at a pin, and that job has no `if:`. The pin is judged by section 3.4. |
| `W4` | `tripcord.yml` | `with.fail-on` is present and is one of `low`, `medium`, `high`. |
| `W5` | `tripcord.yml` | `with` sets none of `binary`, `ref`, or `path` (other than `.`). This is a denylist: new inputs stay allowed. |
| `S1` | Copilot setup step | `run` is `bash .tripcord/bootstrap.sh install` with no `\|\|`, `;`, `&`, `\|`, or newline after it, and the step has no `continue-on-error: true` and no `if:`. |
| `G1` | `.gitattributes` | Every `gitattributesTargets()` path resolves `text eol=lf` (`gitattributesOK`). The target list only grows. |
| `M1` | embed.json | The manifest parses and records every surface it claims. A recorded entry that is absent is `missing`; one the manifest does not record is not. |

`B1`-`B4` cover the bootstrap edits the positives make and the obvious
bypasses. They cannot prove that an arbitrary shell script is safe. That
residual risk is covered by the writer-witness rule (section 3.3), and in
pull requests by the base comparison.

### 3.3 Classifying an owned file or entry

For `bootstrap.sh`, `tripcord.yml`, each hook entry, and the Copilot step,
`compare` and `entryState` become the following decision. Here `got` is the
content digest and `recorded` is the embed.json digest.

1. `got == current render`: OK, as today.
2. `got` is in `knownRenders`, the compiled historical renders (section
   3.5): `outdated`, **low**, "an older Tripcord wrote this; rerun `init
   --embed --force`". This replaces `stale`, which no committed fixture
   uses except the forged-digest case, handled in step 4.
3. `got != recorded` and step 2 did not match: `changed`, **high**. This
   is version-independent, because every `init` writes a file equal to the
   digest it records, so a mismatch means an edit after `init`.
4. `got == recorded`, the render is unknown, and the tripcord.yml pin is
   in the closed set (writer witness): `changed`, **high**, with payload
   `invariant: "witness"`. A known pin means a writer this scanner knows,
   whose renders it has compiled. This holds because, from this change on,
   **every template change bumps `WorkflowPin`**
   (`TestTemplateChangeNeedsRepin`, section 3.5). This step keeps today's
   strength against forged digests in any scan whose pin is known.
5. `got == recorded`, the render is unknown, and the pin is unknown:
   `unverified`, **info**, with payload `reason: "unknown-render"` and a
   fix: "This file was likely written by a newer Tripcord than this
   scanner; scan locally with the latest Tripcord."
6. In every case, a failing semantic invariant (section 3.2) reports
   `changed`, **high**, with payload `invariant: "<id>"`. It is merged into
   the item for the same subject, so each subject still has one item.

Three related rules:

- **Unknown structure.** A manifest `schema` of `tripcord.embed/vN` with
  N > 1, a harness the scanner does not know, or a hook event the manifest
  records that the scanner does not know: `unverified`, **info**. The
  semantic and pin checks still run, so bumping the schema does not dodge
  them.
- **Missing entries.** `missing` is HIGH only for what the manifest records
  (`M1`), plus the floor every version writes: bootstrap.sh, embed.json,
  tripcord.yml, the `H1` entry per wired harness, and `G1`. An event a newer
  writer dropped and did not record is `unverified`, **info**.
- **States that do not change:** `removed`, `dropped`, `repinned`,
  `weakened`, `local-disabled`, `local-policy`, `unreadable` (unparseable),
  and the leftover path. They are already version-independent.
  `base-repinned` stays HIGH.

Requirement (1) holds for every render surface. A newer writer always
gives `got == recorded`. Its pin is unknown to an older scanner, because
template changes require a new pin, so it lands in step 5 (info) unless
an invariant fails.

### 3.4 Workflow pin

This applies to `jobs.*.uses` of `tripcord.yml`. The closed set is
`{WorkflowPin} ∪ KnownWorkflowPins` (section 3.5).

| Pin | Trusted scan (local `scan`, pre-commit `--staged`) | CI scan |
|---|---|---|
| Not this repository's `.github/workflows/tripcord-pr.yml`, or a ref that is not 40 lowercase hex (short SHA, `main`, `refs/heads/...`, `v0.1.0`) | `pin-malformed`, **high** | `pin-malformed`, **high** |
| `== WorkflowPin` | OK | OK |
| In `KnownWorkflowPins` | `outdated`, **low** | `outdated`, **low** |
| `== --executing-workflow` SHA | (the flag is CI-only) | OK |
| Any other 40-hex (unknown, or a fork-network SHA) | `pin-unknown`, **high** | `unverified`, **info** ("cannot verify pin in CI; scan locally with the latest Tripcord") |

**Flag.** The proposed flag is `tripcord scan --executing-workflow
<owner>/<repo>/<path>@<sha>`.

- The value is
  `${{ job.workflow_repository }}/${{ job.workflow_file_path }}@${{ job.workflow_sha }}`,
  set by the composite action, which can read `job.*` directly as the spike
  shows.
- The action passes it only when `job.workflow_repository` is
  `github.action_repository` and `job.workflow_file_path` is
  `.github/workflows/tripcord-pr.yml`. A user who calls the action directly
  gets no flag, and GHES leaves the value empty.
- The scanner rejects (exit 2, config error) a value whose repository is not
  `project.Repository`, whose path is not
  `.github/workflows/tripcord-pr.yml`, or whose SHA is not 40 lowercase hex.
  A misconfiguration therefore fails loudly.
- The flag marks the scan as a CI scan. It can only *accept* a pin equal to
  its SHA. It never upgrades or suppresses anything else.
- It is a flag only, never read from a policy file or the repository.

**Scan context.** `CheckOptions` gains `Context` (`Trusted` is the zero
value, or `CI`) and `Executing *WorkflowRef`. `cmd/tripcord` selects `CI`
when `--executing-workflow` is given or `GITHUB_ACTIONS=true`. Both are set
by the runner or the workflow, never by the scanned tree. The tests' own
`TestMain` already unsets `GITHUB_ACTIONS`, and the fixture helpers call
`embedded.Check` with zero options, so fixtures stay trusted and unchanged.

**Base mode (optional addition).** A change to the pin between base and
head reports the existing `repinned` state, with subject `workflow-pin`
and HIGH severity. It is the same review a binary re-pin gets. No existing
JSON fixture changes the workflow pin, so none changes.

**Conflict between requirements (1) and (5), stated explicitly.** In a
trusted scan by a scanner *older* than the writer, the newer pin is unknown,
so (5) says HIGH while (1) says no HIGH for a newer embed. Offline, nothing
distinguishes "a newer writer" from "a forged pin plus a forged
embed.json". The recommended resolution needs sign-off:

- `pin-unknown` drops to `unverified`/info in a trusted scan only when all
  of these hold:
  - the scanner is a release build;
  - embed.json `version` is valid semver and strictly greater than the
    scanner's own version;
  - tripcord.yml matches its recorded digest.

  Lying about `version` gains nothing at hook time, because `bootstrap.sh`
  only runs a cached binary whose SHA-256 matches the pinned sum (`B3` and
  `B4`), and a nonexistent version fails closed.
- Otherwise (5) wins: `pin-unknown` stays HIGH, with the fix text "If this
  embed was written by a newer Tripcord than this scanner (vX), upgrade and
  rescan; otherwise this is not a Tripcord commit."
- To keep the remaining case rare, `init --embed` on a release build
  should refuse a `--version` older than itself. Otherwise the pinned
  binary's own `scan --config` in `bootstrap.sh` is an older trusted
  scanner.

### 3.5 Go shapes

`internal/embedded/pins.go`:

```go
// KnownWorkflowPins are earlier values of WorkflowPin, oldest first.
// A repin PR appends the WorkflowPin it replaces, in the same change;
// entries are never edited or removed. A pin here is accepted as
// outdated (low), never as current. TestKnownWorkflowPinsShape checks
// the format; TestReleaseGateKnownWorkflowPins checks each against main.
var KnownWorkflowPins = []string{
	// Seeded by the fix PR as empty; the first repin PR appends
	// "6a1279565e9e41e9dec163e6bedf07f2647a2c67" (main@6a12795).
	// 8b33b1b and 6e1d5db are deliberately absent: their
	// tripcord-pr.yml pins an action without the embed check.
}

// WorkflowRef is a parsed --executing-workflow value.
type WorkflowRef struct{ Repository, Path, SHA string }

// PinState is the verdict on a tripcord.yml pin.
type PinState int

const (
	PinCurrent   PinState = iota // == WorkflowPin
	PinExecuting                 // == CheckOptions.Executing.SHA (CI only)
	PinKnown                     // in KnownWorkflowPins: outdated (low)
	PinUnknown                   // 40-hex, in neither: high (trusted) / info (CI)
	PinMalformed                 // not tripcord-pr.yml@<40-hex>: high
)

func ClassifyPin(uses string, executing *WorkflowRef) PinState
```

`internal/embedded/known_renders.go` is generated by `go run
./scripts/knownrenders` and must not be edited by hand:

```go
type renderSet struct {
	bootstrapTemplate []string            // sha256 of bootstrap.sh with the TRIPCORD_VERSION line and sum arms replaced by placeholders
	workflowTemplate  []string            // sha256 of tripcord.yml with the pin and its main@ comment replaced
	hooks             map[string][]string // "<harness>/<event>" -> HookEntry.SHA256
	copilotStep       []string
}

// knownRenders maps each pin in {WorkflowPin} ∪ KnownWorkflowPins to
// every render an init that wrote that pin produced.
var knownRenders = map[string]renderSet{ /* generated */ }
```

The generator walks every main commit from `8b33b1b` onward. At each one it
builds `cmd/tripcord`, runs `init --embed --harness claude,cursor,copilot`
with a fixed dummy pin, normalizes the output, and groups the result by that
commit's `WorkflowPin`. The pin `6a12795` already maps to several templates
(`c8e5bdd`, `85a380a`, `f81d1bf`, `ff4b401`, `3f322e4`). That is fine,
because it is a set.

**Repin PR procedure.**

1. Set `WorkflowPin` to the new SHA.
2. Append the old SHA to `KnownWorkflowPins`.
3. Run `go run ./scripts/knownrenders`.
4. Run `UPDATE_GOLDEN=1 go test ./cmd/tripcord -run TestCFG016FixturesMatchInit`,
   which rewrites the pin inside the fixtures, as every repin does today.
5. Update the `docs/github-action.md` pin.

**Tests that keep it honest.**

- `TestKnownWorkflowPinsShape` (always runs): every entry is 40 lowercase
  hex, entries are unique, `WorkflowPin` is not in the list, and
  `knownRenders` keys equal `{WorkflowPin} ∪ KnownWorkflowPins`.
- `TestTemplateChangeNeedsRepin` (needs history): the current render must
  be in `knownRenders[WorkflowPin]` as committed on `origin/main`. Changing
  a template without a new pin fails with "template changed: repin
  WorkflowPin".
- `TestReleaseGateKnownWorkflowPins` (`TRIPCORD_RELEASE_GATE=1`, next to
  `TestReleaseGatePinnedActionHasEmbedCheck`). For every entry, and for
  `WorkflowPin`, it checks that:
  - the commit is in the clone;
  - `merge-base --is-ancestor <pin> origin/main` holds;
  - the commit descends from `embedCheckMinimum`;
  - its `tripcord-pr.yml` exists and pins an action whose tree has
    `func Check(` and the `base` input (reusing `actionPins`);
  - the list is ordered, with each entry an ancestor of the next and of
    `WorkflowPin`;
  - the list is a prefix-extension of `origin/main`'s list (append-only),
    and the old `knownRenders` entries are byte-identical.

### 3.6 Rule changes (`rules/TC-CFG-016.yaml` only)

- Add a `low` clause for `state == "outdated"`.
- Add an `info` clause for `state == "unverified"`, titled "Tripcord could
  not verify this part of the guard". Its fix is "scan locally with the
  latest Tripcord (`tripcord scan`); this scanner is older than the embed
  or runs in CI".
- Add `high` clauses for `pin-unknown` and `pin-malformed`.
- Keep the existing HIGH clauses for `missing`, `changed`, `unreadable`,
  `removed`, `dropped`, `repinned`, `weakened`, `local-disabled`, and
  `local-policy`.
- Leave `stale` defined but unused, or remove it.

## 4. Existing positives: what catches each, in any scan

Every positive keeps its single severity, `high`, and `expect.yaml` is
untouched. "Exact" means step 3 of section 3.3 (`got != recorded`), which
is version-independent. The table lists the semantic check that also
catches each mutation when an attacker forges embed.json to match.

| Positive | Today (current scanner) | Version-independent detection after the change |
|---|---|---|
| `claude-disable-all-hooks` | disableAllHooks clause | `H6`, unchanged (not an embed check) |
| `copilot-hooks-file-disable-all-hooks` | disableAllHooks | `H6`, unchanged |
| `copilot-settings-disable-all-hooks` | disableAllHooks | `H6`, unchanged |
| `gemini-hooks-config-disabled` | hooksConfig.enabled false | unchanged (not an embed check) |
| `embed-claude-disable-all-hooks` | disableAllHooks | `H6` |
| `embed-claude-wiring-removed` (guard removed) | `missing` (PreToolUse, SessionStart) | `M1` (manifest records both) + `H1` |
| `embed-claude-only-wiring-removed` | `missing` ×2 | `M1` + `H1` |
| `embed-cursor-wiring-removed` | `missing` ×2 | `M1` + `H1` |
| `embed-copilot-wiring-removed` | `missing` ×2 | `M1` + `H1` |
| `embed-claude-not-tripcord` | `missing` PreToolUse | `H1` (no entry runs bootstrap.sh hook) |
| `embed-cursor-not-tripcord` | `missing` preToolUse | `H1` |
| `embed-copilot-not-tripcord` | `missing` preToolUse | `H1` |
| `embed-claude-hook-loosened` (**onFailure continue**) | `changed` | exact + **`H2`** |
| `embed-workflow-changed` (**fail-on critical**) | `changed` | exact + **`W4`** |
| `embed-bootstrap-changed` (**bootstrap: checksum gate → `false`**) | `changed` | exact + **`B4`** |
| `embed-bootstrap-digest-forged` (**forged digest**) | `stale` (the only thing catching it today) | **`B4`** + writer witness (step 4: known pin, unknown render) |
| `embed-copilot-step-changed` (**install \|\| true**) | `changed` | exact + **`S1`** |
| `embed-gitattributes-weakened` (**-text**) | `changed` | **`G1`** (already semantic) |
| `embed-gitattributes-removed` | `missing` | `G1` floor |
| `embed-bootstrap-missing` | `missing` | floor (bootstrap.sh) |
| `embed-manifest-unreadable` | `unreadable` | unchanged (`{` does not parse) |
| `embed-guard-removed-workflow-left` | leftover: `missing` bootstrap and manifest | unchanged (leftover path) |
| `embed-leftover-claude-hook` | leftover: `missing` | unchanged |
| `base-guard-removed.json` (**guard removed**) | `removed` | unchanged (base-relative) |
| `base-embed-removed.json` | `removed` | unchanged |
| `base-harness-dropped.json` | `dropped` | unchanged |
| `base-repinned.json` | `repinned` | unchanged, **stays HIGH** |
| `base-policy-weakened.json` | `weakened` | unchanged |
| `local-claude-disable-all-hooks.json` | `local-disabled` | unchanged |
| `local-copilot-disable-all-hooks.json` | `local-disabled` | unchanged |
| `base-local-disable-all-hooks.json` | `local-disabled` | unchanged |
| `local-policy-tracked.json` | `local-policy` | unchanged |
| `base-local-policy-tracked.json` | `local-policy` | unchanged |

Why no fixture changes:

- The fix PR changes neither a template nor `WorkflowPin`, so
  `TestCFG016FixturesMatchInit` still matches.
- Every committed fixture is a current render with the current pin, so the
  new `outdated`, `unverified`, and pin states never fire on them.
- Semantic results are merged into the existing per-subject item. They add
  the `invariant` payload key only in steps 4 and 5, which no JSON fixture
  reaches.
- The forged-digest positive moves from `stale` to `changed`, and both are
  HIGH. That positive is a txtar fixture checked by severity only.

## 5. Limits

- **In-workflow checking is self-attestation.** The embed's `tripcord.yml`
  comes from the pull request: `pull_request` runs the merge commit's
  workflow file. A PR can point it at
  this repository's `tripcord-pr.yml` at a fork-network SHA
  or anywhere else, and then the scanner itself is that code.
  `--executing-workflow` only proves "the pin equals what is running", and
  the semantic checks only bind an honest scanner. The real defenses live
  outside the PR:
  - trusted scans (local and pre-commit), which apply the closed set;
  - base-mode `repinned` on review;
  - CODEOWNERS on `.tripcord/**` and `.github/workflows/tripcord.yml`;
  - a GitHub ruleset "required workflow", whose workflow does not come from
    the PR.
- `job.workflow_*` is not available on GHES. There the CI path falls back to
  the closed set, and unknown pins are `info`.
- `B1`-`B4` cannot prove that an arbitrary script is safe. In CI, with the
  pin unknown to the scanner, a forged-digest `bootstrap.sh` that keeps
  `B1`-`B4` is only `info`. A trusted scan catches it through the writer
  witness or `pin-unknown`.
- Rollout. Embeds pinned to `6a12795` keep running action `8b33b1b` and
  keep failing until the user reruns `init --embed --force` after the
  repin chain below. The fix PR itself cannot help those embeds.

### Rollout order

1. **Fix PR (F):** checker, invariants, rule clauses, `KnownWorkflowPins`,
   `knownRenders`, the action's `--executing-workflow` plumbing, and tests.
   No template or pin change.
2. **Repin PR (G):** `tripcord-pr.yml`'s action pin set to F.
3. **Repin PR (H):** `WorkflowPin` set to G, `6a12795` appended to
   `KnownWorkflowPins`, and fixtures regenerated.

The e2e in section 6 passes from H on.

## 6. Tests to add

The tests go in new files: `internal/embedded/check_skew_test.go`,
`cmd/tripcord/skew_e2e_test.go`, and new fixtures only if they carry a
single severity.

- **Outdated pin:** the pin is the last entry of `KnownWorkflowPins`, with
  the digest rewritten as `init` would. Expect exactly one `outdated` (low),
  trusted and CI.
- **Unknown pin:** a random 40-hex SHA.
  - Trusted: `pin-unknown`, high.
  - CI without the flag: `unverified`, info.
  - CI with the flag equal to the pin: no item.
  - CI with the flag not equal: `unverified`, info.
  - The release-build refinement from section 3.4, if adopted: the version
    is greater than the scanner's, so `unverified`, info.
- **Short, branch, and tag pins:** a table of `6a12795`, a 39-hex SHA,
  uppercase hex, `main`, `refs/heads/main`, `v0.1.0`,
  another owner's `tripcord/...` at `WorkflowPin`, and `.../tripcord-pr-comment.yml@...`.
  Expect `pin-malformed`, high, in both contexts.
- **Fork SHA:** a 40-hex SHA that is a valid commit only in a fork
  (constant).
  - Trusted: `pin-unknown`, high.
  - CI with the flag equal to it: accepted. The test names this as the
    documented self-attestation limit.
  - Base mode: `repinned`, high.
- **Flag parsing** (cmd): a wrong repository, wrong path, non-hex SHA, or
  an empty `@` exits 2. A valid value sets the CI context.
- **Newer embed, older scanner**, one subtest for each of the 6 surfaces:
  Claude `SessionStart`, Claude `PreToolUse`, Cursor `preToolUse`, Copilot
  `preToolUse`, `tripcord.yml`, and `bootstrap.sh`.
  - Setup: apply a benign "future" change to that surface, such as an extra
    harmless key in the hook entry, an extra comment line in bootstrap.sh,
    or an extra `paths:` entry in tripcord.yml. Then rewrite the embed.json
    digest the way a newer `init` would, and set the pin to an unknown
    40-hex SHA.
  - Assert, in CI with and without the flag: no high item for that
    subject, exactly one `unverified` info.
  - Variant: the same change plus an invariant break (`H2`, `H3`, `H4`,
    `H5`, `W4`, `B4`). Expect `changed`, high, with the `invariant` set.
  - Variant: the same benign change with a known pin. Expect `changed`,
    high (writer witness).
- **Older embed, newer scanner:** take a render from `knownRenders` that is
  not current. Expect `outdated`, low. For a pre-`--on-failure` hook
  render, also expect `H5`, high.
- **Unknown structure:** schema `tripcord.embed/v2` is `unverified` info
  and not `unreadable`. A harness or event the scanner does not know is
  `unverified` info. A recorded event that is absent is `missing`, high. An
  unrecorded absent event is `unverified` info.
- **Invariant contract:** `TestInvariantsHoldForInit` checks every harness
  combination, and `TestInvariantsAppendOnly` checks against
  `origin/main`.
- **E2E `TestVersionSkewCIScanner`** (`TRIPCORD_RELEASE_GATE=1` and a CI
  job with full history). It reproduces the 6 HIGH today and passes after
  step 3 of the rollout:
  1. Build `cmd/tripcord` from this tree. Run `init --embed --version
     0.1.0 --sha256 linux-x64=<64 hex>` in a temporary git repository.
  2. Read `git show <WorkflowPin>:.github/workflows/tripcord-pr.yml`, and
     take its `actions/tripcord@<A>` with `actionPins`.
  3. Run `git archive A`, extract it with no `.git`, and run
     `CGO_ENABLED=0 go build -trimpath ./cmd/tripcord` inside it: exactly
     what the action does.
  4. Run that binary with `scan <repo> --format json`, with
     `GITHUB_ACTIONS=true`. Add
     `--executing-workflow` naming this repository's `tripcord-pr.yml` at `WorkflowPin`
     when `scan --help` lists the flag.
  5. Assert that no TC-CFG-016 finding is high or critical. Today this
     fails with exactly the 6 subjects in section 1. After F, G, and H it
     passes, with at most `unverified` info.

## 7. Option, not a decision: CI runs a published binary verified by digest

Distribution is Victor's decision, so this is presented as an option only.

**Is it the clean path?** Partly. It removes "CI builds A from source", but
version skew comes from *which version* CI runs, not from *how* it gets it.
A published binary chosen by W or A is still older than the writer. The
variant that actually closes the gap is this:

- CI runs the release the embed itself pins: embed.json `version` plus its
  `linux-x64` SHA-256.
- For a pull request, the pin is taken from the **base** revision's
  embed.json, so the PR cannot choose it. The head's pin is used only when
  the base has no embed.
- The download comes from the project's releases and is verified against
  that digest before it runs.

That is the same binary the hooks run. When `init` and `--version` are the
same release, which is the normal case, the scanner and the writer are the
same version, and the degrade rules above only cover the remaining edge
cases.

Advantages:

- Same bits as the hooks, and reproducible.
- No Go toolchain in CI, and faster.
- No fork-network source build.
- Provenance can be checked with GitHub artifact attestations or SLSA.

Costs and risks:

- It needs published releases with checksums and signing or attestations
  (release infrastructure, key custody).
- CI needs network egress to the release host, which rules out
  air-gapped runners and GHES without a mirror.
- A head-only pin (first PR) lets the PR choose an **older official
  release**. That calls for a minimum-version floor compiled into W.
- The embed must pin `linux-x64` (today `--sha256` is per platform and
  optional per platform).
- Unreleased main cannot be tested this way. Keep the source-build path for
  this repository's own CI (`./.github/actions/tripcord`).
- It still does not remove the self-attestation limit in section 5.

A smaller step that needs no release infrastructure: `tripcord-pr.yml`
passes `ref: ${{ job.workflow_sha }}` to the action, which already supports
`ref`. The action then builds W instead of A, which narrows the gap from
"A behind" to "one pin behind". It does not close the gap, because W cannot
contain its own SHA.
