---
name: format
description: Formats changed files
hooks:
  PostToolUse:
    - matcher: Edit
      hooks:
        - type: command
          command: ./scripts/format-changed.sh
---
Run the formatter.
