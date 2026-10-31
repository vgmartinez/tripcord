package output

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

func renderJSONL(writer io.Writer, findings []model.Finding) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	for _, finding := range findings {
		if err := encoder.Encode(finding); err != nil {
			return err
		}
	}
	return nil
}

func renderText(writer io.Writer, findings []model.Finding) error {
	for _, finding := range findings {
		location := displayLocation(finding.Location)
		if location == "" {
			location = "unknown location"
		}
		if _, err := fmt.Fprintf(writer, "%s %s %s: %s\n", strings.ToUpper(finding.Severity.String()), finding.Rule, location, finding.Title); err != nil {
			return err
		}
		for _, evidence := range finding.Evidence {
			if evidence.Excerpt == "" {
				continue
			}
			if _, err := fmt.Fprintf(writer, "  evidence: %s\n", evidence.Excerpt); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(writer, "  fix: %s\n  fingerprint: %s\n", finding.Fix, finding.Fingerprint); err != nil {
			return err
		}
	}
	summary := Summarize(findings)
	_, err := fmt.Fprintf(writer, "%d finding(s): %d critical, %d high, %d medium, %d low\n", summary.Findings, summary.Critical, summary.High, summary.Medium, summary.Low)
	return err
}

func renderGHA(writer io.Writer, findings []model.Finding, options Options) error {
	for _, finding := range findings {
		command := "warning"
		if finding.Severity == model.SeverityHigh || finding.Severity == model.SeverityCritical {
			command = "error"
		}
		properties := []string{}
		if uri, ok := repoRelativeURI(finding.Location, options.RepoRoot); ok {
			properties = append(properties, "file="+escapeGHAProperty(uri))
			if finding.Location.Line != nil {
				properties = append(properties, "line="+strconv.Itoa(*finding.Location.Line))
			}
		}
		message := fmt.Sprintf("%s [%s] %s (%s)", finding.Title, finding.Rule, finding.Fix, finding.Fingerprint)
		if _, err := fmt.Fprintf(writer, "::%s%s::%s\n", command, ghaProperties(properties), escapeGHAData(message)); err != nil {
			return err
		}
	}
	return nil
}

func renderMarkdown(writer io.Writer, findings []model.Finding) error {
	summary := Summarize(findings)
	if _, err := fmt.Fprintf(writer, "## Tripcord findings\n\n%d finding(s): %d critical, %d high, %d medium, %d low.\n\n", summary.Findings, summary.Critical, summary.High, summary.Medium, summary.Low); err != nil {
		return err
	}
	if len(findings) == 0 {
		_, err := io.WriteString(writer, "No findings.\n")
		return err
	}
	if _, err := io.WriteString(writer, "| Severity | Rule | Location | Finding |\n| --- | --- | --- | --- |\n"); err != nil {
		return err
	}
	for index, finding := range findings {
		location := displayLocation(finding.Location)
		if location == "" {
			location = "—"
		}
		if _, err := fmt.Fprintf(writer, "| %s | %s | %s | %s |\n", markdownTable(finding.Severity.String()), markdownTable(finding.Rule), markdownTable(location), markdownTable(finding.Title)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "\n### %s — %s\n\n%s\n\n", markdownText(finding.Rule), markdownText(finding.Title), markdownText(finding.Fix)); err != nil {
			return err
		}
		for _, evidence := range finding.Evidence {
			if evidence.Excerpt == "" {
				continue
			}
			if _, err := fmt.Fprintf(writer, "> Evidence: %s\n\n", markdownText(evidence.Excerpt)); err != nil {
				return err
			}
		}
		suffix := "\n"
		if index < len(findings)-1 {
			suffix = "\n\n"
		}
		if _, err := fmt.Fprintf(writer, "Fingerprint: `%s`%s", markdownCode(finding.Fingerprint), suffix); err != nil {
			return err
		}
	}
	return nil
}

func displayLocation(location model.Location) string {
	if location.Path == "" {
		return ""
	}
	if location.Line == nil {
		return location.Path
	}
	return location.Path + ":" + strconv.Itoa(*location.Line)
}

func repoRelativeURI(location model.Location, root string) (string, bool) {
	if location.Path == "" || location.Scope != model.ScopeRepo {
		return "", false
	}
	path := filepath.Clean(location.Path)
	if filepath.IsAbs(path) {
		if root == "" {
			return "", false
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return "", false
		}
		path = relative
	}
	if path == "." || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(path), true
}

func ghaProperties(properties []string) string {
	if len(properties) == 0 {
		return ""
	}
	return " " + strings.Join(properties, ",")
}

func escapeGHAData(value string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value)
}

func escapeGHAProperty(value string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(value)
}

func markdownText(value string) string {
	return strings.NewReplacer("\\", "\\\\", "`", "\\`", "<", "&lt;", ">", "&gt;").Replace(value)
}

func markdownTable(value string) string {
	return strings.ReplaceAll(markdownText(value), "|", "\\|")
}

func markdownCode(value string) string {
	return strings.ReplaceAll(markdownText(value), "`", "\\`")
}
