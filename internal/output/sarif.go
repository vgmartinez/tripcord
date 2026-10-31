package output

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
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
	Tool               sarifTool                        `json:"tool"`
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult                    `json:"results"`
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
	Properties          *sarifProperties  `json:"properties,omitempty"`
}

type sarifProperties struct {
	Tripcord sarifTripcord `json:"tripcord"`
}

type sarifTripcord struct {
	Scope string `json:"scope"`
	Path  string `json:"path"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI         string        `json:"uri,omitempty"`
	URIBaseID   string        `json:"uriBaseId,omitempty"`
	Description *sarifMessage `json:"description,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func renderSARIF(writer io.Writer, findings []model.Finding, options Options) error {
	mode, err := sarifNonRepoMode(options)
	if err != nil {
		return err
	}
	rules := make(map[string]string, len(findings))
	results := make([]sarifResult, 0, len(findings))
	var bases map[string]sarifArtifactLocation
	for _, finding := range findings {
		rules[finding.Rule] = finding.Title
		level, err := sarifLevel(finding.Severity)
		if err != nil {
			return err
		}
		ref := locate(finding.Location, options.RepoRoot)
		result := sarifResult{
			RuleID:  finding.Rule,
			Level:   level,
			Message: sarifMessage{Text: resultMessage(finding, ref.path)},
			PartialFingerprints: map[string]string{
				"tripcord/fingerprint": finding.Fingerprint,
			},
		}
		if ref.path != "" {
			result.Properties = &sarifProperties{Tripcord: sarifTripcord{Scope: ref.scope, Path: ref.path}}
		}
		switch ref.kind {
		case locNone:
		case locRepo:
			result.Locations = []sarifLocation{{PhysicalLocation: physicalLocation(ref, false)}}
		case locUser, locManaged:
			if mode == SARIFNonRepoLogical {
				result.Locations = []sarifLocation{{LogicalLocations: []sarifLogicalLocation{logicalLocation(ref)}}}
				break
			}
			if bases == nil {
				bases = map[string]sarifArtifactLocation{}
			}
			bases[ref.baseID] = sarifArtifactLocation{Description: &sarifMessage{Text: uriBaseDescription(ref.baseID)}}
			result.Locations = []sarifLocation{{PhysicalLocation: physicalLocation(ref, true)}}
		default:
			return fmt.Errorf("output: unhandled location kind %d", ref.kind)
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
			Tool:               sarifTool{Driver: sarifDriver{Name: "tripcord", Rules: sarifRules}},
			OriginalURIBaseIDs: bases,
			Results:            results,
		}},
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	return encoder.Encode(log)
}

func sarifNonRepoMode(options Options) (SARIFNonRepoLocation, error) {
	switch options.NonRepoSARIF {
	case "", DefaultSARIFNonRepoLocation:
		return DefaultSARIFNonRepoLocation, nil
	case SARIFNonRepoLogical:
		return SARIFNonRepoLogical, nil
	default:
		return "", fmt.Errorf("output SARIF location %q: supported values are %q and %q", options.NonRepoSARIF, SARIFNonRepoURIBase, SARIFNonRepoLogical)
	}
}

func resultMessage(finding model.Finding, path string) string {
	text := finding.Title + ": " + finding.Fix
	if path == "" {
		return text
	}
	return text + " (" + path + ")"
}

func physicalLocation(ref locationRef, withBase bool) *sarifPhysicalLocation {
	artifact := sarifArtifactLocation{URI: ref.uri}
	if withBase {
		artifact.URIBaseID = ref.baseID
	}
	location := &sarifPhysicalLocation{ArtifactLocation: artifact}
	if ref.line != nil {
		location.Region = &sarifRegion{StartLine: *ref.line}
	}
	return location
}

func logicalLocation(ref locationRef) sarifLogicalLocation {
	return sarifLogicalLocation{
		Name:               path.Base(ref.path),
		FullyQualifiedName: ref.path,
		Kind:               ref.scope,
	}
}

func uriBaseDescription(id string) string {
	switch id {
	case URIBaseUserHome:
		return "The user's home directory."
	case URIBaseManaged:
		return "Managed configuration location."
	default:
		return ""
	}
}

// SARIF's level enum is none, note, warning, and error. low maps to note.
func sarifLevel(severity model.Severity) (string, error) {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error", nil
	case model.SeverityMedium:
		return "warning", nil
	case model.SeverityLow:
		return "note", nil
	default:
		return "", fmt.Errorf("output: unhandled severity %q", severity)
	}
}
