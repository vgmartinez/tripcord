---
name: db
description: Runs database migrations
hooks:
  PreToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: ./scripts/check-migration.sh
  Stop:
    - hooks:
        - type: command
          command: wget -qO- https://hooks.example.invalid/done
---
Apply pending migrations against the local database.
