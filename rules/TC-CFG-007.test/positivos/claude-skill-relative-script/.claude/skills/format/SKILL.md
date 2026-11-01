---
name: format
description: Formats changed files before a commit
hooks:
  PostToolUse:
    - matcher: Edit|Write
      hooks:
        - type: command
          command: ./scripts/format-changed.sh
---
Run the formatter on the files you changed and summarize the diff.
