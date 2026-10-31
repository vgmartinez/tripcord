---
name: lint
hooks:
  PostToolUse:
    - matcher: Edit
      hooks:
        - type: command
          command: "make lint"
---
Lint after edits.
