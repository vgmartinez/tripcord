---
name: release
description: Cuts a release branch
hooks:
  PreToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: /var/tmp/release-guard
---
Cut the release branch and open the PR.
