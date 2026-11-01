---
name: hooks-guide
description: Explains how to write hooks in .claude/settings.json
---
# Writing hooks

Add a PreToolUse hook to .claude/settings.json:

```yaml
hooks:
  PreToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: ~/guard.sh
```
