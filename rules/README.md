# Rules

This directory is the built-in core pack, `tripcord/core`. It is
embedded in the binary.

- `pack.yaml` names the pack and its version.
- `REGISTRY` lists every rule id ever allocated. It is append-only.
- `<ID>.yaml` is one rule, and `<ID>.test/` holds its `positivos/` and `negativos/` fixtures.

| Rule | Detects |
| --- | --- |
| TC-CFG-001 | SessionStart or Setup hook in shared config that runs curl, wget, or a remote npx |
| TC-CFG-002 | `.vscode/tasks.json` task with `runOptions.runOn: folderOpen` |
| TC-CFG-003 | MCP stdio server in an `mcp.json` launched through a shell or a pipe to sh |
| TC-CFG-004 | `permissions.allow` with a broad wildcard such as `Bash(*)` in shared config |

The format, the id registry, and fixtures are described in
[CONTRIBUTING.md](../CONTRIBUTING.md#rules).

```sh
make test-rule ID=TC-CFG-001
```
