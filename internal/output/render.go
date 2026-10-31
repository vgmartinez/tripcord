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
		if err := encoder.Encode(capFinding(publishedFinding(finding, options.RepoRoot))); err != nil {
			return err
		}
	}
	_, err := writer.Write(escapeJSONUnsafe(buffer.Bytes()))
	return err
}

// presentFindings rewrites managed home paths inside config ids on a
// copy of each evidence list. The fingerprint field is not touched.
// Callers must pass a slice they own: the stored findings keep their ids.
func presentFindings(findings []model.Finding) {
	for i := range findings {
		findings[i].Evidence = presentEvidence(findings[i].Evidence)
	}
}

func presentEvidence(in []model.Evidence) []model.Evidence {
	if in == nil {
		return nil
	}
	out := make([]model.Evidence, len(in))
	for i, item := range in {
		if item.Config != nil {
			cfg := *item.Config
			cfg.ID = presentConfigID(cfg.ID)
			item.Config = &cfg
		}
		out[i] = item
	}
	return out
}

// capFinding limits every attacker-controlled string. The fingerprint is
// kept intact. Evidence and refs are copied, so the stored finding is not.
func capFinding(finding model.Finding) model.Finding {
	finding.Rule = truncateSanitized(finding.Rule, MaxFieldBytes)
	finding.Title = truncateSanitized(finding.Title, MaxFieldBytes)
	finding.Fix = truncateSanitized(finding.Fix, MaxFieldBytes)
	finding.Location.Session = truncateSanitized(finding.Location.Session, MaxFieldBytes)
	finding.Location.Path = truncateSanitized(finding.Location.Path, MaxFieldBytes)
	if finding.Evidence != nil {
		evidence := make([]model.Evidence, len(finding.Evidence))
		for i, item := range finding.Evidence {
			item.Event = truncateSanitized(item.Event, MaxFieldBytes)
			item.Excerpt = truncateSanitized(item.Excerpt, MaxFieldBytes)
			if item.Config != nil {
				cfg := *item.Config
				cfg.ID = truncateSanitized(cfg.ID, MaxFieldBytes)
				cfg.Key = truncateSanitized(cfg.Key, MaxFieldBytes)
				item.Config = &cfg
			}
			evidence[i] = item
		}
		finding.Evidence = evidence
	}
	if finding.Refs != nil {
		refs := make([]string, len(finding.Refs))
		for i, ref := range finding.Refs {
			refs[i] = truncateSanitized(ref, MaxFieldBytes)
		}
		finding.Refs = refs
	}
	return finding
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
			present(finding.Rule),
			present(location),
			present(finding.Title))}
		for _, evidence := range finding.Evidence {
			if evidence.Excerpt != "" {
				parts = append(parts, "evidence: "+present(evidence.Excerpt))
			}
		}
		parts = append(parts, "fix: "+present(finding.Fix), "fingerprint: "+present(finding.Fingerprint))
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
		message := fmt.Sprintf("%s [%s] %s (%s)", ghaData(finding.Title), ghaData(finding.Rule), ghaData(finding.Fix), ghaData(finding.Fingerprint))
		switch ref.kind {
		case locNone:
		case locRepo:
			properties = append(properties, "file="+ghaProperty(ref.path))
			if ref.line != nil {
				properties = append(properties, "line="+strconv.Itoa(*ref.line))
			}
		case locUser, locManaged:
			properties = append(properties, "title="+ghaProperty(ref.display()))
			message += " " + ghaData(ref.display())
		default:
			return fmt.Errorf("output: unhandled location kind %d", ref.kind)
		}
		fmt.Fprintf(&b, "::%s%s::%s\n", command, ghaProperties(properties), message)
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
	return truncateSanitized(escapeControls(strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value)), MaxFieldBytes)
}

// ghaProperty applies GitHub's property escaping, which adds ":" and ",",
// then removes every remaining control and bidi character.
func ghaProperty(value string) string {
	return truncateSanitized(escapeControls(strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(value)), MaxFieldBytes)
}
