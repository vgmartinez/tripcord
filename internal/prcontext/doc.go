// Package prcontext decides whether a pull request looks agent-authored.
//
// It reads four signals: the GitHub login of the PR author and of each
// commit's author and committer, Co-authored-by trailers, a branch-name
// prefix, and git-ai authorship notes under refs/notes/ai. A match is a
// hint for TC-CFG-014, which pr-context evaluates separately. Detection
// itself does not fail a job.
package prcontext
