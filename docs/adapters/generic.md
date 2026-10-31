# Shared skills adapter

`.agents/skills/**/SKILL.md` and `.github/skills/**/SKILL.md` are read by
more than one coding agent. The generic adapter discovers them and emits
`model.ConfigItem` values with harness `generic`, including frontmatter
`hooks` and `mcpServers`. The fingerprint uses that harness, so it stays
the same when the Copilot adapter lands and reads the same files.

Claude Code's own `.claude/skills/` files stay on the Claude adapter.
See [claude.md](claude.md).

The adapter uses the shared safe reader: in-repository symlinks are
followed, a symlink that leaves the repository is reported, and special
files are not read. Limits match the Claude adapter. `tripcord scan`
selects it by autodetection, or with `--harness generic`. `--scope user`
and `--scope managed` skip it, because these files are repository files.
