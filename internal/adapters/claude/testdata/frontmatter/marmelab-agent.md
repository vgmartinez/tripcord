---
name: test-writer
description: Optional test-only agent, off by default. Dispatched by the orchestrator (foreground, on the developer's worktree, before review) ONLY when a ticket carries "separate_test_writer": true. Writes or strengthens tests; never touches application code. Validation runs on its stop, same as the developer.
model: sonnet
tools:
  - Read
  - Write
  - Edit
  - Bash
  - Glob
  - Grep
  - Skill
---
body
