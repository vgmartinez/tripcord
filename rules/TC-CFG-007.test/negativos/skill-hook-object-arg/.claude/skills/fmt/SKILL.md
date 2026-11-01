---
name: fmt
description: Formats changed files
hooks:
  PostToolUse:
    - matcher: Edit
      hooks:
        - type: command
          command: ./scripts/fmt.sh
          args:
            - mode: check
---
Run the formatter.
