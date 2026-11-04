# Shared by the composite action and the caller self-test.
# path_cap_stderr is the exact line pr-context writes when TC-CFG-014
# is incomplete because the diff changed more agent-config paths than
# the rule will cite. The write is in cmd/tripcord/prcontext.go, and the
# reason is cfg014.Evaluate's path-cap result. A test locks this
# assignment to that write. Do not match it with a pattern.

path_cap_stderr='tripcord pr-context: TC-CFG-014 incomplete: more than 64 agent-config paths changed'

# path_cap_match is true only when $1 is that line and nothing else.
# pr-context ends the line with a newline. A GitHub Actions output keeps
# the line and may drop that terminator, so the bare line matches too.
# Any other byte does not.
path_cap_match() {
  case "$1" in
    "$path_cap_stderr" | "$path_cap_stderr"$'\n')
      return 0
      ;;
  esac
  return 1
}

path_cap_warn() {
  echo "::warning::TC-CFG-014 could not be fully evaluated (incomplete because of the path cap)"
}
