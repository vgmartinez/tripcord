package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

const sarifSchemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

// semverPattern is SemVer 2.0.0 without a leading "v".
var semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                        `json:"tool"`
	Invocations        []sarifInvocation                `json:"invocations,omitempty"`
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult                    `json:"results"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Message sarifMessage `json:"message"`
	Level   string       `json:"level"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription"`
	Help                 sarifMessage        `json:"help"`
	HelpURI              string              `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig     `json:"defaultConfiguration"`
	Properties           sarifRuleProperties `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
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
	Scope string `json:"scope,omitempty"`
	Path  string `json:"path,omitempty"`
	// Mode is the "sig:" discriminator mode that produced
	// Fingerprint (see model.FingerprintMode): "k1", "s1", or omitted
	// when the finding's evidence carries no discriminator at all.
	Mode string `json:"fingerprintMode,omitempty"`
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

// sarifRuleInfo is rule metadata gathered from findings. The first finding
// of a rule in sort order supplies text; the highest severity seen sets the
// default level and security-severity.
type sarifRuleInfo struct {
	title    string
	fix      string
	helpURI  string
	severity model.Severity
}

func renderSARIF(writer io.Writer, findings []model.Finding, diags []Diagnostic, options Options) error {
	mode, err := sarifNonRepoMode(options)
	if err != nil {
		return err
	}
	rules := map[string]*sarifRuleInfo{}
	results := make([]sarifResult, 0, len(findings))
	var bases map[string]sarifArtifactLocation
	for _, finding := range findings {
		if info, ok := rules[finding.Rule]; ok {
			if compareSeverity(finding.Severity, info.severity) > 0 {
				info.severity = finding.Severity
			}
			if info.helpURI == "" {
				info.helpURI = helpURI(finding.Refs)
			}
		} else {
			rules[finding.Rule] = &sarifRuleInfo{
				title:    finding.Title,
				fix:      finding.Fix,
				helpURI:  helpURI(finding.Refs),
				severity: finding.Severity,
			}
		}
		level, err := sarifLevel(finding.Severity)
		if err != nil {
			return err
		}
		ref := locate(finding.Location, options.RepoRoot)
		fpMode := model.FingerprintMode(finding.Evidence)
		result := sarifResult{
			RuleID:  finding.Rule,
			Level:   level,
			Message: sarifMessage{Text: resultMessage(finding, ref.display())},
			PartialFingerprints: map[string]string{
				"tripcord/fingerprint": finding.Fingerprint,
			},
		}
		if ref.kind != locNone || fpMode != "" {
			tripcord := sarifTripcord{Mode: fpMode}
			if ref.kind != locNone {
				tripcord.Scope, tripcord.Path = ref.scope, present(ref.path)
			}
			result.Properties = &sarifProperties{Tripcord: tripcord}
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

	sarifRules, err := buildSARIFRules(rules, options.Rules)
	if err != nil {
		return err
	}
	version, semantic := toolVersions(options.ToolVersion)
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:            "tripcord",
			Version:         version,
			SemanticVersion: semantic,
			Rules:           sarifRules,
		}},
		OriginalURIBaseIDs: bases,
		Results:            results,
	}
	if len(diags) > 0 {
		notes := make([]sarifNotification, len(diags))
		for i, d := range diags {
			notes[i] = sarifNotification{Message: sarifMessage{Text: sarifText(d.Text())}, Level: "error"}
		}
		run.Invocations = []sarifInvocation{{
			ExecutionSuccessful:        false,
			ToolExecutionNotifications: notes,
		}}
	}
	log := sarifLog{
		Schema:  sarifSchemaURL,
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(log); err != nil {
		return err
	}
	_, err = writer.Write(escapeJSONUnsafe(buffer.Bytes()))
	return err
}

func buildSARIFRules(rules map[string]*sarifRuleInfo, catalog map[string]RuleText) ([]sarifRule, error) {
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		info := rules[id]
		level, err := sarifLevel(info.severity)
		if err != nil {
			return nil, err
		}
		score, err := securitySeverity(info.severity)
		if err != nil {
			return nil, err
		}
		full, help, helpURI := catalogRuleText(id, info, catalog)
		out = append(out, sarifRule{
			ID:                   id,
			ShortDescription:     sarifMessage{Text: sarifText(info.title)},
			FullDescription:      sarifMessage{Text: sarifText(full)},
			Help:                 sarifMessage{Text: sarifText(help)},
			HelpURI:              helpURI,
			DefaultConfiguration: sarifRuleConfig{Level: level},
			Properties:           sarifRuleProperties{Tags: []string{"security"}, SecuritySeverity: score},
		})
	}
	return out, nil
}

// catalogRuleText uses the rule catalog for fullDescription, help, and
// helpUri, and the finding for anything the catalog does not supply.
// TODO(PR 5): the catalog is the rule pack; this fallback stays.
func catalogRuleText(id string, info *sarifRuleInfo, catalog map[string]RuleText) (string, string, string) {
	full, help, uri := info.title, info.fix, info.helpURI
	extra, ok := catalog[id]
	if !ok {
		return full, help, uri
	}
	if extra.FullDescription != "" {
		full = extra.FullDescription
	}
	if extra.Help != "" {
		help = extra.Help
	}
	if extra.HelpURI != "" {
		if safe := helpURI([]string{extra.HelpURI}); safe != "" {
			uri = safe
		}
	}
	return full, help, uri
}

// helpURI returns the first http or https ref with a host. Other schemes
// and refs carrying control or bidi characters are skipped.
func helpURI(refs []string) string {
	for _, ref := range refs {
		if strings.IndexFunc(ref, isUnsafeRune) >= 0 {
			continue
		}
		u, err := url.Parse(ref)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		return u.String()
	}
	return ""
}

// toolVersions returns the driver version and a SemVer 2.0.0 form of it.
// A build version that is not SemVer, such as "dev", reports 0.0.0-dev.
// That dev form is the intended value, not a placeholder to be filled in.
func toolVersions(version string) (string, string) {
	version = strings.TrimSpace(version)
	if version == "" {
		version = "dev"
	}
	semantic := strings.TrimPrefix(version, "v")
	if !semverPattern.MatchString(semantic) {
		semantic = "0.0.0-dev"
	}
	return escapeControls(version), semantic
}

func sarifNonRepoMode(options Options) (SARIFNonRepoLocation, error) {
	switch options.NonRepoSARIF {
	case "":
		return DefaultSARIFNonRepoLocation, nil
	case SARIFNonRepoLogical, SARIFNonRepoURIBase:
		return options.NonRepoSARIF, nil
	default:
		return "", fmt.Errorf("output SARIF location %q: supported values are %q and %q", options.NonRepoSARIF, SARIFNonRepoLogical, SARIFNonRepoURIBase)
	}
}

// sarifText escapes controls and format characters, then "[" and "]" so a
// SARIF viewer cannot render an embedded Markdown link, then caps the field.
func sarifText(value string) string {
	return truncateSanitized(escapeBrackets(escapeControls(value)), MaxFieldBytes)
}

func escapeBrackets(value string) string {
	return strings.NewReplacer(`[`, `\[`, `]`, `\]`).Replace(value)
}

func resultMessage(finding model.Finding, location string) string {
	text := sarifText(finding.Title) + ": " + sarifText(finding.Fix)
	if location == "" {
		return text
	}
	return text + " (" + sarifText(location) + ")"
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
		Name:               present(path.Base(ref.path)),
		FullyQualifiedName: present(ref.path),
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

// sarifLevel maps severities to SARIF levels. SARIF has no "notice", so low
// is "note".
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

// securitySeverity is the GitHub code scanning score for a severity.
func securitySeverity(severity model.Severity) (string, error) {
	switch severity {
	case model.SeverityCritical:
		return "9.5", nil
	case model.SeverityHigh:
		return "8.0", nil
	case model.SeverityMedium:
		return "5.5", nil
	case model.SeverityLow:
		return "3.0", nil
	default:
		return "", fmt.Errorf("output: unhandled severity %q", severity)
	}
}
