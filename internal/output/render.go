package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vgmartinez/tripcord/internal/exitcode"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/project"
)

// renderJSONL writes one tripcord.finding/v1 document per line. Values
// round-trip, except that encoding/json replaces each invalid UTF-8 byte
// with U+FFFD. The location path is the display path from locate; the
// fingerprint is the one stored on the finding. See docs/output.md.
// diagnosticSchema identifies a discovery problem in a JSONL report. It is
// not a tripcord.finding/v1 document.
const diagnosticSchema = "tripcord.diagnostic/v1"

// findingDocument adds the fingerprint mode to a Finding's JSON/JSONL
// rendering without adding a field to Finding itself, which is the
// frozen tripcord.finding/v1 wire type. MarshalJSON appends
// "fingerprintMode" after Finding's own MarshalJSON output (preserving
// its nil-slice-to-[] normalization), so a finding with no "sig:"
// discriminator (FingerprintMode is "") renders byte-for-byte as before;
// tripcord.finding/v1 accepts an unrecognized property on any object
// (see schemas/tripcord.finding.v1.schema.json), so adding it is not a
// breaking schema change.
type findingDocument struct {
	Finding         model.Finding
	FingerprintMode string
}

func (d findingDocument) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(d.Finding)
	if err != nil {
		return nil, err
	}
	if d.FingerprintMode == "" {
		return base, nil
	}
	extra, err := json.Marshal(d.FingerprintMode)
	if err != nil {
		return nil, err
	}
	out := bytes.TrimSuffix(base, []byte("}"))
	out = append(out, []byte(`,"fingerprintMode":`)...)
	out = append(out, extra...)
	out = append(out, '}')
	return out, nil
}

type diagnosticDocument struct {
	Schema     string `json:"schema"`
	Incomplete bool   `json:"incomplete"`
	Level      string `json:"level"`
	Harness    string `json:"harness"`
	Scope      string `json:"scope,omitempty"`
	Path       string `json:"path,omitempty"`
	Message    string `json:"message"`
}

func renderJSONL(writer io.Writer, findings []model.Finding, diags []Diagnostic, options Options) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	for _, finding := range findings {
		published := capFinding(publishedFinding(finding, options.RepoRoot))
		doc := findingDocument{Finding: published, FingerprintMode: model.FingerprintMode(published.Evidence)}
		if err := encoder.Encode(doc); err != nil {
			return err
		}
	}
	for _, d := range diags {
		doc := diagnosticDocument{
			Schema:     diagnosticSchema,
			Incomplete: !d.Informational,
			Level:      diagnosticLevel(d),
			Harness:    truncateSanitized(d.Harness, MaxFieldBytes),
			Scope:      truncateSanitized(d.Scope, MaxFieldBytes),
			Path:       truncateSanitized(d.Path, MaxFieldBytes),
			Message:    truncateSanitized(d.Message, MaxFieldBytes),
		}
		if err := encoder.Encode(doc); err != nil {
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

// textWidth is the visible width of a compact text line. Terminal
// hyperlinks around a rule id do not count.
const textWidth = 80

// textDetailHint tells a reader how to get the evidence, fix, and fingerprint.
const textDetailHint = "re-run with -v for details"

// ruleDocID matches a catalog rule id. Only those ids become links.
var ruleDocID = regexp.MustCompile(`^TC-[A-Z]+-[0-9]{3}$`)

// renderText writes the human view. The default is one screen: a summary
// with the exit verdict, one line per finding, and a hint. -v
// (Options.Verbose) writes the detailed line instead. Every
// attacker-controlled field goes through present, so a finding line
// starts with the severity. JSON and SARIF do not call this.
func renderText(writer io.Writer, findings []model.Finding, diags []Diagnostic, options Options) error {
	if options.Verbose {
		return renderTextDetail(writer, findings, diags, options.RepoRoot)
	}
	var b strings.Builder
	writeTextSummary(&b, findings, diags, textExitCode(findings, diags, options))
	writeTextDiagnostics(&b, diags)
	for _, finding := range findings {
		b.WriteString(compactFindingLine(finding, options.RepoRoot, options.ToolVersion, options.Hyperlinks))
		b.WriteByte('\n')
	}
	b.WriteString(textDetailHint)
	b.WriteByte('\n')
	_, err := io.WriteString(writer, b.String())
	return err
}

// renderTextDetail is the text view from before the one-screen summary:
// one line per finding with evidence, fix, and fingerprint, then the counts.
func renderTextDetail(writer io.Writer, findings []model.Finding, diags []Diagnostic, root string) error {
	var b strings.Builder
	writeTextDiagnostics(&b, diags)
	for _, finding := range findings {
		location := "-"
		if ref := locate(finding.Location, root); ref.kind != locNone {
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
		b.WriteByte('\n')
	}
	summary := Summarize(findings)
	fmt.Fprintf(&b, "%d finding(s): %d critical, %d high, %d medium, %d low; %d warning(s)\n", summary.Findings, summary.Critical, summary.High, summary.Medium, summary.Low, informationalDiagnostics(diags))
	_, err := io.WriteString(writer, b.String())
	return err
}

func writeTextDiagnostics(b *strings.Builder, diags []Diagnostic) {
	for _, d := range diags {
		prefix := "diagnostic: "
		if d.Informational {
			prefix = "warning: "
		}
		b.WriteString(prefix + present(d.Text()) + "\n")
	}
	if hasBlockingDiagnostic(diags) {
		b.WriteString("scan incomplete\n")
	}
}

func writeTextSummary(b *strings.Builder, findings []model.Finding, diags []Diagnostic, code int) {
	summary := Summarize(findings)
	fmt.Fprintf(b, "%d finding(s): %d critical, %d high, %d medium, %d low; %d warning(s); exit %d\n", summary.Findings, summary.Critical, summary.High, summary.Medium, summary.Low, informationalDiagnostics(diags), code)
}

// textExitCode is the exit the compact summary prints. A caller that
// already decided (audit mode, a changed --fail-on) passes it in
// Options.TextExit. Otherwise a blocking diagnostic is exit 3 and a
// finding at or above high, the scan default, is exit 1.
func textExitCode(findings []model.Finding, diags []Diagnostic, options Options) int {
	if options.TextExit != nil {
		return *options.TextExit
	}
	if hasBlockingDiagnostic(diags) {
		return int(exitcode.Config)
	}
	for _, finding := range findings {
		cmp, err := finding.Severity.Compare(model.SeverityHigh)
		if err == nil && cmp >= 0 {
			return int(exitcode.Findings)
		}
	}
	return int(exitcode.OK)
}

// compactFindingLine is one finding: severity, rule id, short title,
// path:line. The rule id is a terminal hyperlink to its doc. The
// visible line is at most textWidth columns.
func compactFindingLine(finding model.Finding, root, version string, hyperlinks bool) string {
	sev := strings.ToUpper(finding.Severity.String())
	rule := present(finding.Rule)
	title := present(finding.Title)
	loc := "-"
	if ref := locate(finding.Location, root); ref.kind != locNone {
		loc = present(ref.display())
	}
	shownTitle, shownLoc := fitFinding(sev, rule, title, loc)
	line := sev + " " + linkRuleID(rule, version, hyperlinks)
	if shownTitle != "" {
		line += " " + shownTitle
	}
	return line + " " + shownLoc
}

// fitFinding shortens the title, then the path, so the visible line
// fits in textWidth. The rule id is counted without its hyperlink.
// Titles break at a word boundary; paths keep a hard cut so a
// component is not dropped whole.
func fitFinding(sev, rule, title, loc string) (string, string) {
	overhead := utf8.RuneCountInString(sev) + utf8.RuneCountInString(rule) + utf8.RuneCountInString(loc) + 3
	room := textWidth - overhead
	if room >= 1 {
		return shortenVisible(title, room), loc
	}
	// No room for a title. Drop it and shorten the path into what remains.
	locRoom := textWidth - (utf8.RuneCountInString(sev) + utf8.RuneCountInString(rule) + 2)
	if locRoom < 1 {
		locRoom = 1
	}
	return "", shortenHard(loc, locRoom)
}

// shortenVisible caps s to room runes without splitting an escape
// token. When the cut falls inside a word, it backs up to the last
// whitespace so the ellipsis does not sit mid-word or after a space,
// unless that would leave fewer than half of room columns, or fewer
// than 8, in which case the hard cut is kept so a single long word
// still shows something.
func shortenVisible(s string, room int) string {
	if room <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= room {
		return s
	}
	if room == 1 {
		return "…"
	}
	kept, rest := takeVisible(s, room-1)
	if rest != "" && kept != "" {
		next, _ := utf8.DecodeRuneInString(rest)
		last, _ := utf8.DecodeLastRuneInString(kept)
		if next != utf8.RuneError && last != utf8.RuneError && !unicode.IsSpace(next) && !unicode.IsSpace(last) {
			if cut := lastSpaceOffset(kept); cut >= 0 {
				w := utf8.RuneCountInString(kept[:cut])
				minKeep := 8
				if half := room / 2; half > minKeep {
					minKeep = half
				}
				if w >= minKeep {
					kept = kept[:cut]
				}
			}
		}
	}
	return trimTitleTail(kept) + "…"
}

// shortenHard caps s to room runes without splitting an escape token
// and without looking for a word boundary. Paths use this so a cut
// stays at the same column as before.
func shortenHard(s string, room int) string {
	if room <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= room {
		return s
	}
	if room == 1 {
		return "…"
	}
	kept, _ := takeVisible(s, room-1)
	return kept + "…"
}

// takeVisible returns the longest prefix of s whose tokens fit in
// budget runes, and the rest. The cut is always on a token boundary.
func takeVisible(s string, budget int) (string, string) {
	width := 0
	i := 0
	for i < len(s) {
		n := nextToken(s, i)
		w := utf8.RuneCountInString(s[i : i+n])
		if width+w > budget {
			break
		}
		width += w
		i += n
	}
	return s[:i], s[i:]
}

func lastSpaceOffset(s string) int {
	cut := -1
	for i := 0; i < len(s); {
		n := nextToken(s, i)
		if isSpaceToken(s[i : i+n]) {
			cut = i
		}
		i += n
	}
	return cut
}

func trimTitleTail(s string) string {
	for s != "" {
		last := 0
		for i := 0; i < len(s); {
			last = i
			i += nextToken(s, i)
		}
		if !isTitleTrimToken(s[last:]) {
			break
		}
		s = s[:last]
	}
	return s
}

func isSpaceToken(tok string) bool {
	r, n := utf8.DecodeRuneInString(tok)
	return n == len(tok) && r != utf8.RuneError && unicode.IsSpace(r)
}

func isTitleTrimToken(tok string) bool {
	r, n := utf8.DecodeRuneInString(tok)
	if n != len(tok) || r == utf8.RuneError {
		return false
	}
	return unicode.IsSpace(r) || r == ',' || r == ':'
}

// releaseTag is a release version with an optional pre-release suffix.
// The release workflow stamps this form with -X main.version=vX.Y.Z.
var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// prBuildVersion is a PR build stamped as v0.0.0-pr.N. Those builds
// have no git tag, so rule-doc links stay on main.
var prBuildVersion = regexp.MustCompile(`^v0\.0\.0-pr\.\d+$`)

// docRef returns the git ref used in rule-doc URLs. A release tag is
// used as-is, except PR builds, which have no tag. Anything else,
// including dev and an empty version, uses main.
func docRef(version string) string {
	if releaseTag.MatchString(version) && !prBuildVersion.MatchString(version) {
		return version
	}
	return "main"
}

func isDocRef(ref string) bool {
	return ref == docRef(ref)
}

// ruleDocBase is the URL prefix shared by linkRuleID and
// textHyperlinkLen: https://github.com/<repo>/blob/<ref>/docs/rules/.
func ruleDocBase(version string) string {
	return "https://github.com/" + project.Repository + "/blob/" + docRef(version) + "/docs/rules/"
}

func ruleDocURL(id, version string) string {
	return ruleDocBase(version) + id + ".md"
}

// ruleDocURI rewrites a docs/rules link on this repository so it
// points at the same ref docRef(version) would use. Other URIs are
// returned unchanged.
func ruleDocURI(uri, version string) string {
	const suffix = ".md"
	prefix := "https://github.com/" + project.Repository + "/blob/"
	if !strings.HasPrefix(uri, prefix) {
		return uri
	}
	rest := uri[len(prefix):]
	_, after, ok := strings.Cut(rest, "/docs/rules/")
	if !ok || !strings.HasSuffix(after, suffix) {
		return uri
	}
	id := strings.TrimSuffix(after, suffix)
	if !ruleDocID.MatchString(id) {
		return uri
	}
	return ruleDocURL(id, version)
}

// linkRuleID wraps a catalog rule id in an OSC 8 hyperlink to its doc.
// Anything else is returned unchanged, so a finding cannot set the URL.
func linkRuleID(id, version string, hyperlinks bool) string {
	if !hyperlinks || !ruleDocID.MatchString(id) {
		return id
	}
	target := ruleDocURL(id, version)
	return "\x1b]8;;" + target + "\x1b\\" + id + "\x1b]8;;\x1b\\"
}

// textHyperlinkLen is the byte length of one OSC 8 sequence compact text
// emits, either the opener (the rule-doc URL included) or the closer.
// It is zero when s does not start with one of those, so an escaped
// control in a finding is not treated as a link. The opener is
// recognized for main and for release-tag refs, so a longer tag URL
// does not count toward visible width.
func textHyperlinkLen(s string) int {
	const closer = "\x1b]8;;\x1b\\"
	openPrefix := "\x1b]8;;https://github.com/" + project.Repository + "/blob/"
	if strings.HasPrefix(s, openPrefix) {
		rest := s[len(openPrefix):]
		ref, after, ok := strings.Cut(rest, "/docs/rules/")
		if ok && isDocRef(ref) {
			id, _, ok := strings.Cut(after, ".md\x1b\\")
			if ok && ruleDocID.MatchString(id) {
				return len(openPrefix) + len(ref) + len("/docs/rules/") + len(id) + len(".md\x1b\\")
			}
		}
		return 0
	}
	if strings.HasPrefix(s, closer) {
		return len(closer)
	}
	return 0
}

func renderGHA(writer io.Writer, findings []model.Finding, diags []Diagnostic, options Options) error {
	var b strings.Builder
	for _, d := range diags {
		level := "error"
		if d.Informational {
			level = "warning"
		}
		fmt.Fprintf(&b, "::%s::%s\n", level, ghaData(d.Text()))
	}
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

func diagnosticLevel(d Diagnostic) string {
	if d.Informational {
		return "warning"
	}
	return "error"
}

func hasBlockingDiagnostic(diags []Diagnostic) bool {
	for _, d := range diags {
		if !d.Informational {
			return true
		}
	}
	return false
}

func informationalDiagnostics(diags []Diagnostic) int {
	count := 0
	for _, d := range diags {
		if d.Informational {
			count++
		}
	}
	return count
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
	return truncateGHA(escapeControlsKeepBackslash(strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(value)), MaxFieldBytes)
}

// ghaProperty applies GitHub's property escaping, which adds ":" and ",",
// then removes every remaining control and bidi character.
func ghaProperty(value string) string {
	return truncateGHA(escapeControlsKeepBackslash(strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(value)), MaxFieldBytes)
}

// truncateGHA keeps workflow-command %XX sequences whole. GitHub decodes
// these escapes, so emitting a partial one would make a capped annotation
// ambiguous and can change how its tail is displayed.
func truncateGHA(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	best := 0
	for i := 0; i < len(value); {
		next := i + ghaTokenLen(value, i)
		marker := truncationMarker(len(value) - next)
		if next+len(marker) > limit {
			break
		}
		best = next
		i = next
	}
	if best == 0 {
		return truncationMarker(len(value))
	}
	return value[:best] + truncationMarker(len(value)-best)
}

func ghaTokenLen(value string, i int) int {
	if i+3 <= len(value) && value[i] == '%' && isHex(value[i+1]) && isHex(value[i+2]) {
		return 3
	}
	return nextToken(value, i)
}
