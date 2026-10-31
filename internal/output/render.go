package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// renderJSONL writes one tripcord.finding/v1 document per line. Values
// round-trip, except that encoding/json replaces each invalid UTF-8 byte
// with U+FFFD. The location path is the display path from locate; the
// fingerprint is the one stored on the finding. See docs/output.md.
func renderJSONL(writer io.Writer, findings []model.Finding, options Options) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	for _, finding := range findings {
		if err := encoder.Encode(publishedFinding(finding, options.RepoRoot)); err != nil {
			return err
		}
	}
	_, err := writer.Write(escapeJSONUnsafe(buffer.Bytes()))
	return err
}

// publishedFinding returns a copy whose location path is the one locate
// allows. A location locate drops loses its path and line.
func publishedFinding(finding model.Finding, root string) model.Finding {
	ref := locate(finding.Location, root)
	finding.Location.Path = ref.path
	if ref.kind == locNone {
		finding.Location.Line = nil
	}
	return finding
}

// renderText writes one line per finding and a summary line. Every field
// goes through escapeControls, so a line always starts with the severity.
func renderText(writer io.Writer, findings []model.Finding, options Options) error {
	var b strings.Builder
	for _, finding := range findings {
		location := "-"
		if ref := locate(finding.Location, options.RepoRoot); ref.kind != locNone {
			location = ref.display()
		}
		parts := []string{fmt.Sprintf("%s %s %s: %s",
			strings.ToUpper(finding.Severity.String()),
			escapeControls(finding.Rule),
			escapeControls(location),
			escapeControls(finding.Title))}
		for _, evidence := range finding.Evidence {
			if evidence.Excerpt != "" {
				parts = append(parts, "evidence: "+escapeControls(evidence.Excerpt))
			}
		}
		parts = append(parts, "fix: "+escapeControls(finding.Fix), "fingerprint: "+escapeControls(finding.Fingerprint))
		b.WriteString(strings.Join(parts, " | "))
		b.WriteString("\n")
	}
	summary := Summarize(findings)
	fmt.Fprintf(&b, "%d finding(s): %d critical, %d high, %d medium, %d low\n", summary.Findings, summary.Critical, summary.High, summary.Medium, summary.Low)
	_, err := io.WriteString(writer, b.String())
	return err
}

func renderGHA(writer io.Writer, findings []model.Finding, options Options) error {
	var b strings.Builder
	for _, finding := range findings {
		command, err := ghaCommand(finding.Severity)
		if err != nil {
			return err
		}
		ref := locate(finding.Location, options.RepoRoot)
		properties := []string{}
		message := fmt.Sprintf("%s [%s] %s (%s)", finding.Title, finding.Rule, finding.Fix, finding.Fingerprint)
		switch ref.kind {
		case locNone:
		case locRepo:
			properties = append(properties, "file="+ghaProperty(ref.path))
			if ref.line != nil {
				properties = append(properties, "line="+strconv.Itoa(*ref.line))
			}
		case locUser, locManaged:
			properties = append(properties, "title="+ghaProperty(ref.display()))
			message += " " + ref.display()
		default:
			return fmt.Errorf("output: unhandled location kind %d", ref.kind)
		}
		fmt.Fprintf(&b, "::%s%s::%s\n", command, ghaProperties(properties), ghaData(message))
	}
	_, err := io.WriteString(writer, b.String())
	return err
}

func ghaCommand(severity model.Severity) (string, error) {
	switch severity {
	case model.SeverityLow:
		return "notice", nil
	case model.SeverityMedium:
		return "warning", nil
	case model.SeverityHigh:
		return "error", nil
	case model.SeverityCritical:
		return "error", nil
	default:
		return "", fmt.Errorf("output: unhandled severity %q", severity)
	}
}

func ghaProperties(properties []string) string {
	if len(properties) == 0 {
		return ""
	}
	return " " + strings.Join(properties, ",")
}

// ghaData applies GitHub's workflow command data escaping, then removes
// every remaining control and bidi character.
func ghaData(value string) string {
	return escapeControls(strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value))
}

// ghaProperty applies GitHub's property escaping, which adds ":" and ",",
// then removes every remaining control and bidi character.
func ghaProperty(value string) string {
	return escapeControls(strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(value))
}
