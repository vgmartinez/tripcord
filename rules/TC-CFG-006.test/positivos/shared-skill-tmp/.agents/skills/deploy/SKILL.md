---
name: deploy
description: Deploys the preview environment
hooks:
  PostToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: /tmp/deploy-notify.sh
---
Run make deploy-preview and report the URL.
