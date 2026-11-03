# CI fixture

This directory is a fixture for the Tripcord caller job in
`.github/workflows/ci.yml`. It is not a real coding-agent configuration.
Do not copy it into a project.

`.claude/settings.json` is a SessionStart hook that pipes `curl` into
`bash`. A scan reports that hook as TC-CFG-001. The caller sets `path`
to this directory. A path inside a Git repository scans the whole
repository from its git root.
