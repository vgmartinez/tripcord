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
//
// Summary-table cells keep backslashes as written, including Windows paths.
// A literal "|" is escaped so it cannot end the cell. Detail sections show
// the same backslashes. See docs/output.md.
//
// The comment stays within MaxMarkdownBytes, under GitHub's 65536-character
// limit. Findings that do not fit are omitted whole, and the comment ends
// with "N more findings omitted".
func renderMarkdown(writer io.Writer, findings []model.Finding, options Options) error {
	summary := Summarize(findings)
	var head strings.Builder
	fmt.Fprintf(&head, "## Tripcord findings\n\nTotal: %d. Critical: %d, high: %d, medium: %d, low: %d.\n", summary.Findings, summary.Critical, summary.High, summary.Medium, summary.Low)
	if len(findings) == 0 {
		head.WriteString("\nNo findings.\n")
		_, err := io.WriteString(writer, head.String())
		return err
	}
	const tableHead = "\n| Severity | Rule | Location | Finding |\n| --- | --- | --- | --- |\n"
	rows := make([]string, len(findings))
	bodies := make([]string, len(findings))
	for i, finding := range findings {
		ref := locate(finding.Location, options.RepoRoot)
		rows[i] = markdownRow(finding, ref)
		bodies[i] = markdownBody(finding, ref)
	}
	included := 0
	used := head.Len() + len(tableHead)
	for i := range findings {
		piece := len(rows[i]) + len(bodies[i])
		extra := 0
		if omitted := len(findings) - (i + 1); omitted > 0 {
			extra = len(omissionLine(omitted))
		}
		if used+piece+extra > MaxMarkdownBytes {
			break
		}
		used += piece
		included++
	}
	var b strings.Builder
	b.WriteString(head.String())
	if included == 0 {
		b.WriteString(omissionLine(len(findings)))
		_, err := io.WriteString(writer, b.String())
		return err
	}
	b.WriteString(tableHead)
	for i := 0; i < included; i++ {
		b.WriteString(rows[i])
	}
	for i := 0; i < included; i++ {
		b.WriteString(bodies[i])
	}
	if included < len(findings) {
		b.WriteString(omissionLine(len(findings) - included))
	}
	_, err := io.WriteString(writer, b.String())
	return err
}

func omissionLine(n int) string {
	return fmt.Sprintf("\n%d more findings omitted\n", n)
}

func markdownRow(finding model.Finding, ref locationRef) string {
	location := "—"
	if ref.kind != locNone {
		location = tableCode(ref.display())
	}
	return fmt.Sprintf("| %s | %s | %s | %s |\n", tableCode(finding.Severity.String()), tableCode(finding.Rule), location, tableCode(finding.Title))
}

func markdownBody(finding model.Finding, ref locationRef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s — %s\n\nFix: %s\n", inlineCode(finding.Rule), inlineCode(finding.Title), inlineCode(finding.Fix))
	if ref.kind != locNone {
		fmt.Fprintf(&b, "\nLocation: %s\n", inlineCode(ref.display()))
	}
	for _, evidence := range finding.Evidence {
		if evidence.Excerpt != "" {
			fmt.Fprintf(&b, "\nEvidence:\n\n%s\n", fencedCode(evidence.Excerpt))
		}
	}
	fmt.Fprintf(&b, "\nFingerprint: %s\n", inlineCode(finding.Fingerprint))
	return b.String()
}

// markdownValue sanitizes, breaks @mentions, then caps. The U+200B inserted
// by breakMentions is this sink's mention breaker. It is added after
// sanitization, so the format-character escape does not remove it, and
// before the cap, so the breaker counts toward MaxFieldBytes.
func markdownValue(value string) string {
	return truncateSanitized(breakMentions(escapeControlsKeepBackslash(value)), MaxFieldBytes)
}

func breakMentions(value string) string {
	return strings.ReplaceAll(value, "@", "@\u200b")
}

// inlineCode wraps value in a code span whose delimiter is longer than any
// backtick run inside it.
func inlineCode(value string) string {
	return codeSpan(markdownValue(value))
}

// tableCode is inlineCode for a GFM table cell. Backslashes stay literal.
// "|" is escaped so the table parser does not treat it as a cell boundary.
func tableCode(value string) string {
	sanitized := truncateSanitized(breakMentions(escapeControlsKeepBackslash(value)), MaxFieldBytes)
	return strings.ReplaceAll(codeSpan(sanitized), "|", `\|`)
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
