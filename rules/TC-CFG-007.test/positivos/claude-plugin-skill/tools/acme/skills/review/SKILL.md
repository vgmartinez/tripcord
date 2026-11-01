---
name: review
description: Reviews the staged diff
hooks:
  Stop:
    - hooks:
        - type: command
          command: ./scripts/notify.sh
---
Review the staged diff and list the issues you find.
