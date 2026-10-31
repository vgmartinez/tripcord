package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// renderMarkdown writes a PR comment or step summary. Attacker-controlled
// text only appears inside code spans or fenced code blocks, so links,
// images, HTML, entities, autolinks, emphasis, and #123 references are
// inert. Mentions are broken with U+200B, and every value is one line.
func renderMarkdown(writer io.Writer, findings []model.Finding, options Options) error {
	var b strings.Builder
	summary := Summarize(findings)
	fmt.Fprintf(&b, "## Tripcord findings\n\nTotal: %d. Critical: %d, high: %d, medium: %d, low: %d.\n", summary.Findings, summary.Critical, summary.High, summary.Medium, summary.Low)
	if len(findings) == 0 {
		b.WriteString("\nNo findings.\n")
		_, err := io.WriteString(writer, b.String())
		return err
	}
	refs := make([]locationRef, len(findings))
	b.WriteString("\n| Severity | Rule | Location | Finding |\n| --- | --- | --- | --- |\n")
	for i, finding := range findings {
		refs[i] = locate(finding.Location, options.RepoRoot)
		location := "—"
		if refs[i].kind != locNone {
			location = tableCode(refs[i].display())
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", tableCode(finding.Severity.String()), tableCode(finding.Rule), location, tableCode(finding.Title))
	}
	for i, finding := range findings {
		fmt.Fprintf(&b, "\n### %s — %s\n\nFix: %s\n", inlineCode(finding.Rule), inlineCode(finding.Title), inlineCode(finding.Fix))
		if refs[i].kind != locNone {
			fmt.Fprintf(&b, "\nLocation: %s\n", inlineCode(refs[i].display()))
		}
		for _, evidence := range finding.Evidence {
			if evidence.Excerpt != "" {
				fmt.Fprintf(&b, "\nEvidence:\n\n%s\n", fencedCode(evidence.Excerpt))
			}
		}
		fmt.Fprintf(&b, "\nFingerprint: %s\n", inlineCode(finding.Fingerprint))
	}
	_, err := io.WriteString(writer, b.String())
	return err
}

// markdownValue collapses value to one line and breaks @mentions.
func markdownValue(value string) string {
	return breakMentions(escapeControlsKeepBackslash(value))
}

func breakMentions(value string) string {
	return strings.ReplaceAll(value, "@", "@\u200b")
}

// inlineCode wraps value in a code span whose delimiter is longer than any
// backtick run inside it.
func inlineCode(value string) string {
	return codeSpan(markdownValue(value))
}

// tableCode is inlineCode for a GFM table cell. The cell scanner reads "\\"
// as an escaped backslash before it looks for "|", so backslashes are
// doubled first; every "|" then follows an odd run of backslashes and stays
// inside the cell.
func tableCode(value string) string {
	return strings.ReplaceAll(codeSpan(breakMentions(escapeControls(value))), "|", `\|`)
}

func codeSpan(value string) string {
	if value == "" {
		return "—"
	}
	fence := strings.Repeat("`", longestBacktickRun(value)+1)
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") || strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
		value = " " + value + " "
	}
	return fence + value + fence
}

// fencedCode puts value on one line inside a backtick fence longer than any
// backtick run in it. A line that would start with "::" gets a leading
// U+200B, so a summary printed to a CI log cannot issue a workflow command.
func fencedCode(value string) string {
	value = markdownValue(value)
	if strings.HasPrefix(strings.TrimLeft(value, " "), "::") {
		value = "\u200b" + value
	}
	fence := strings.Repeat("`", max(3, longestBacktickRun(value)+1))
	return fence + "\n" + value + "\n" + fence
}

func longestBacktickRun(value string) int {
	longest, current := 0, 0
	for _, r := range value {
		if r == '`' {
			current++
			longest = max(longest, current)
			continue
		}
		current = 0
	}
	return longest
}
