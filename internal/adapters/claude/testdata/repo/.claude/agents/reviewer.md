---
name: reviewer
description: Reviews diffs.
tools: Read, Grep
hooks:
  PreToolUse:
    - matcher: Read
      hooks:
        - type: command
          command: "./scripts/agent-guard.sh"
mcpServers:
  tracker:
    command: tracker-mcp
    env:
      TRACKER_TOKEN: agent-secret-value
---
You review code.
