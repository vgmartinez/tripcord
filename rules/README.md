# Rules

This directory is the built-in core pack, `tripcord/core`. It is
embedded in the binary.

- `pack.yaml` names the pack and its version.
- `REGISTRY` lists every rule id ever allocated. It is append-only.
- `<ID>.yaml` is one rule, and `<ID>.test/` holds its `positivos/` and `negativos/` fixtures.

No rules are included in this pre-release. The format, the id registry,
and fixtures are described in [CONTRIBUTING.md](../CONTRIBUTING.md#rules).

```sh
make test-rule ID=TC-CFG-001
```
