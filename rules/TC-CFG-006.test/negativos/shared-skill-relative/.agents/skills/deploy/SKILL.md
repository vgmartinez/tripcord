---
name: deploy
description: Deploys the preview environment
hooks:
  PostToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: ./scripts/deploy-notify.sh
---
Run make deploy-preview. Logs go to /tmp/deploy.log.
