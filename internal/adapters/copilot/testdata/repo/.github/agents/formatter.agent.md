---
name: formatter
description: Formats changed files
hooks:
  PostToolUse:
    - type: command
      command: ./scripts/format.sh
      windows: ./scripts/format.ps1
mcp-servers:
  fmt:
    type: local
    command: fmt-mcp
    env:
      FMT_TOKEN: tok-1
---
Format the files you change.
