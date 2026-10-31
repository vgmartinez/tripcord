# Dev Container adapter

The Dev Container adapter (harness `devcontainer`) discovers Dev
Container configuration statically. It never builds an image, pulls or
installs a Feature, starts a container, runs a lifecycle command, expands
`${localEnv:...}` or `${containerEnv:...}` variables, or invokes git or
docker. Every repository file is treated as attacker-controlled.

Dev Container configuration is not tied to one agent: Codespaces,
Copilot cloud agents, VS Code, Cursor, and the `devcontainer` CLI all run
it when they open the repository in a container. It is therefore its own
harness rather than part of a product adapter, and it runs whenever it is
detected or `--harness devcontainer` is given.

## Locations

Repository scope only (`--scope repo`, the default). There is no user or
managed Dev Container configuration.

| Location | Normalized kinds |
| --- | --- |
| `.devcontainer/devcontainer.json` | `env-setup` |
| `.devcontainer/<name>/devcontainer.json` (one level deep) | `env-setup` |
| `.devcontainer.json` (repository root) | `env-setup` |

These are the locations the tooling offers, all at the repository root;
a `.devcontainer/` in a subdirectory, or a configuration nested deeper
than one level, is not read. Path matching is case-insensitive.

## Normalized payloads

Every key below also carries a trailing content digest of the full
sanitized entry, and, when sanitizing removed anything, a discriminator
over the removed text; see [fingerprint.md](../fingerprint.md#input).

- Lifecycle commands. **`initializeCommand` runs on the host**, before
  the container exists, so it executes with the developer's privileges
  and outside any container isolation; future rules are intended to
  treat it at high severity. `onCreateCommand`, `updateContentCommand`,
  `postCreateCommand`, `postStartCommand`, and `postAttachCommand` run
  in the container. One item per command:
  `{"setting", "form", "name", "command", "runs_on"}`, key
  `["lifecycle", setting, name]`.
  - A string (`"form": "string"`) runs through a shell; `command` is the
    sanitized string.
  - An array (`"form": "array"`) is an argv run without a shell;
    `command` is sanitized element by element, with tool-specific
    credential flags redacted using the shared tool-flag table.
  - An object (`"form": "object"`) runs each named entry in parallel; one
    item per entry, with `name` set, `command` being that entry's string
    or array.
  - Any other value is emitted as `{"form": "other", "value"}` and
    reported.
- Features (`features`): one item per Feature, `{"setting": "features",
  "feature", "options"}`, key `["feature", reference]`. A Feature is an
  install script fetched from an OCI registry, a tarball URL, or a local
  directory and run as root during the image build.
- Environment (`containerEnv`, `remoteEnv`): one item per map,
  `{"setting", "value", "env_keys"}`, with values redacted like MCP
  server `env` values.
- `runArgs` (arguments to `docker run`): sanitized as an argv with the
  shared tool-flag and credential rules. The value of any credential-named
  `NAME=VALUE` element (`SECRET_KEY`, `DB_PASS`, `API_KEY`, ...) is
  redacted, whether it follows `-e`, `--env`, `--env=`, or another flag
  such as `--name`, and also in docker's glued `-eNAME=VALUE` form.
- Settings: one `{"setting", "value"}` item per present key of `image`,
  `build`, `dockerFile`, `context`, `dockerComposeFile`, `service`,
  `runServices`, `mounts`, `workspaceMount`, `workspaceFolder`,
  `privileged`, `capAdd`, `securityOpt`, `init`, `customizations`,
  `overrideFeatureInstallOrder`, `remoteUser`, `containerUser`,
  `updateRemoteUserUID`, `userEnvProbe`, `overrideCommand`,
  `shutdownAction`, and `waitFor`, the value sanitized and secret-looking
  members (`build.args.NPM_TOKEN`) redacted. Other keys (`name`,
  `forwardPorts`, `hostRequirements`, ...) are not emitted.

## Parsing

`devcontainer.json` is parsed as JSONC (comments and trailing commas).
Duplicate keys use the last value and are reported; keys that differ only
by case are reported. Nesting deeper than 64 levels, and files larger
than 1 MiB, fail closed with a diagnostic.

Reads, symlink handling, limits, and diagnostics are those of the
[Claude adapter](claude.md#safe-reads). An escaping symlink under
`.devcontainer/` or at `.devcontainer.json` is reported once, by this
adapter.

## Not scanned in v0

- The `Dockerfile` and Docker Compose files a configuration references.
- Feature sources (`devcontainer-feature.json` and `install.sh` of a
  local Feature, or the contents of a remote one).
- `.devcontainer/devcontainer-lock.json`.
- Templates (`devcontainer-template.json`).
- `.github/dependabot.yml` entries for Dev Container Features.

## Sources

- [Dev Container metadata reference](https://containers.dev/implementors/json_reference/)
- [Dev Container Features](https://containers.dev/implementors/features/)
- [Dev Container specification: configuration locations](https://containers.dev/implementors/spec/#devcontainerjson)
