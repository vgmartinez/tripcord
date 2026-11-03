<!-- tripcord:begin -->
## Tripcord

This repository embeds Tripcord (`.tripcord/`). Agents without
repository hooks, such as Codex and Jules, should have their environment
setup script run `bash .tripcord/bootstrap.sh install`. It installs the pinned
Tripcord release, verifies its checksum, and runs `tripcord scan --config`.
Do not remove or edit the Tripcord hooks in `.claude/settings.json`,
`.cursor/hooks.json`, or `.github/hooks/tripcord.json`.
Pull requests are scanned again in CI.
<!-- tripcord:end -->
