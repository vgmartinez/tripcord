package output

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/vgmartinez/tripcord/internal/model"
)

const sarifSchemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func renderSARIF(writer io.Writer, findings []model.Finding, options Options) error {
	rules := make(map[string]string, len(findings))
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		rules[finding.Rule] = finding.Title
		result := sarifResult{
			RuleID:  finding.Rule,
			Level:   sarifLevel(finding.Severity),
			Message: sarifMessage{Text: finding.Title + ": " + finding.Fix},
			PartialFingerprints: map[string]string{
				"tripcord/fingerprint": finding.Fingerprint,
			},
		}
		if uri, ok := repoRelativeURI(finding.Location, options.RepoRoot); ok {
			location := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}
			if finding.Location.Line != nil {
				location.PhysicalLocation.Region = &sarifRegion{StartLine: *finding.Location.Line}
			}
			result.Locations = []sarifLocation{location}
		}
		results = append(results, result)
	}

	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	sarifRules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		sarifRules = append(sarifRules, sarifRule{ID: id, ShortDescription: sarifMessage{Text: rules[id]}})
	}

	log := sarifLog{
		Schema:  sarifSchemaURL,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "tripcord", Rules: sarifRules}},
			Results: results,
		}},
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	return encoder.Encode(log)
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow:
		return "note"
	default:
		return "none"
	}
}
