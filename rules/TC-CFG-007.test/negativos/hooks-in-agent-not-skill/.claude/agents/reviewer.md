---
name: reviewer
description: Reviews diffs
hooks:
  PreToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: ./scripts/guard.sh
---
Review the diff.
