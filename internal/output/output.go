package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/model"
)

// Format is an output format accepted by scan.
type Format string

const (
	FormatJSON  Format = "json"
	FormatJSONL Format = "jsonl"
	FormatSARIF Format = "sarif"
	FormatText  Format = "text"
	FormatGHA   Format = "gha"
	FormatMD    Format = "md"
)

// SARIFNonRepoLocation selects how user and managed paths are represented.
type SARIFNonRepoLocation string

const (
	// SARIFNonRepoLogical emits logicalLocations and keeps the normalized
	// path in the result message. It is the default because code scanning
	// may ignore uriBaseId and attribute a home-directory finding to the
	// repository file with the same relative path.
	SARIFNonRepoLogical SARIFNonRepoLocation = "logical"
	// SARIFNonRepoURIBase emits a relative artifact URI with uriBaseId
	// USERHOME or MANAGED. It needs a real code scanning upload to verify.
	SARIFNonRepoURIBase SARIFNonRepoLocation = "uri-base"
)

// DefaultSARIFNonRepoLocation is the representation used when Options does
// not select one.
const DefaultSARIFNonRepoLocation = SARIFNonRepoLogical

// Target identifies the supported output destination.
type Target string

const (
	TargetStdout Target = "stdout"
	TargetFile   Target = "file"
)

// Options controls rendering without changing a finding document.
type Options struct {
	// Redactor is required. It runs on every string of every finding before
	// any sink renders it, as defense in depth on top of upstream
	// redaction. Pass DefaultRedactor explicitly when no other is needed.
	Redactor Redactor
	// RepoRoot makes an absolute repository path repository-relative when the
	// path is inside it. Any other absolute repository path is omitted.
	RepoRoot string
	// NonRepoSARIF selects the SARIF form for user and managed paths.
	// The zero value uses DefaultSARIFNonRepoLocation.
	NonRepoSARIF SARIFNonRepoLocation
	// ToolVersion is the build version reported as the SARIF driver
	// version. Empty means "dev", whose semanticVersion is 0.0.0-dev.
	ToolVersion string
	// Rules is optional catalog metadata keyed by rule id. Nil, and any
	// rule absent from the map, falls back to the finding.
	//
	// TODO(PR 5): populate this from the rule catalog. fullDescription,
	// help, and helpUri then come from the catalog, falling back to the
	// finding when the rule is not in it.
	Rules map[string]RuleText
}

// RuleText is catalog metadata for one rule. Empty fields fall back to
// the finding. PR 5 fills Options.Rules; this PR only defines the seam.
type RuleText struct {
	FullDescription string
	Help            string
	HelpURI         string
}

// Sink receives findings and writes a complete result when flushed.
// Implementations buffer findings so every output is sorted deterministically.
type Sink interface {
	Write(model.Finding) error
	Flush() error
}

// Summary describes the findings emitted by a sink.
type Summary struct {
	Findings int
	Low      int
	Medium   int
	High     int
	Critical int
}

// ParseFormat parses a command-line format name.
func ParseFormat(value string) (Format, error) {
	format := Format(value)
	switch format {
	case FormatJSON, FormatJSONL, FormatSARIF, FormatText, FormatGHA, FormatMD:
		return format, nil
	default:
		return "", fmt.Errorf("output format %q: supported formats are json, jsonl, sarif, text, gha, md", value)
	}
}

// SelectSink routes formatName and an optional output path to a local sink.
// json and jsonl both write newline-delimited tripcord.finding/v1 documents.
// An empty outputPath or "-" selects stdout. Any other path selects that file.
// A symlink is rejected. The file is created privately in the same directory
// and replaces the destination only when the handle is closed after a
// successful flush. text, sarif, gha, and md use the same path rule. There
// is no network sink. Close the returned handle when outputPath names a file.
func SelectSink(formatName, outputPath string, stdout io.Writer, options Options) (*Handle, error) {
	format, err := ParseFormat(formatName)
	if err != nil {
		return nil, err
	}
	if outputPath == "" || outputPath == "-" {
		sink, err := NewStdoutSink(format, stdout, options)
		if err != nil {
			return nil, err
		}
		return &Handle{Sink: sink}, nil
	}
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	file, err := newAtomicOutput(outputPath)
	if err != nil {
		return nil, err
	}
	sink, err := NewFileSink(format, file, options)
	if err != nil {
		_ = file.discard()
		return nil, err
	}
	published := &publishSink{inner: sink, file: file}
	return &Handle{Sink: published, close: published.Close}, nil
}

// publishSink writes the finished result to a temporary file and publishes
// it only after Flush succeeds. Close before that removes the temporary
// file and leaves the destination untouched.
type publishSink struct {
	inner Sink
	file  *atomicOutput
}

func (p *publishSink) Write(finding model.Finding) error { return p.inner.Write(finding) }

func (p *publishSink) Flush() error {
	if err := p.inner.Flush(); err != nil {
		return err
	}
	if err := p.file.Sync(); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	p.file.ready = true
	return nil
}

func (p *publishSink) Close() error { return p.file.Close() }

// PathError marks a failure to validate or open the --output destination
// itself: a symlink, a non-regular file, a missing or unwritable parent
// directory, or a permission error reading or creating it. The caller
// should treat it as an invalid flag (an exit-3 configuration error), not
// an internal failure, because it is diagnosed before any finding is
// written.
type PathError struct {
	err error
}

func (e *PathError) Error() string { return e.err.Error() }

func (e *PathError) Unwrap() error { return e.err }

// atomicOutput is a 0600 temporary file in the destination directory.
// Close renames it onto dest only after a successful flush.
type atomicOutput struct {
	*os.File
	dest  string
	ready bool
}

func newAtomicOutput(dest string) (*atomicOutput, error) {
	info, err := os.Lstat(dest)
	switch {
	case err == nil && info.Mode()&os.ModeSymlink != 0:
		return nil, &PathError{err: fmt.Errorf("output path %s is a symlink", dest)}
	case err == nil && !info.Mode().IsRegular():
		return nil, &PathError{err: fmt.Errorf("output path %s is not a regular file", dest)}
	case err != nil && !os.IsNotExist(err):
		return nil, &PathError{err: fmt.Errorf("output path: %w", err)}
	}
	dir := filepath.Dir(dest)
	if dir == "" {
		dir = "."
	}
	file, err := os.CreateTemp(dir, ".tripcord-*.partial")
	if err != nil {
		return nil, &PathError{err: fmt.Errorf("create output file: %w", err)}
	}
	if err := file.Chmod(0o600); err != nil {
		name := file.Name()
		_ = file.Close()
		_ = os.Remove(name)
		return nil, &PathError{err: fmt.Errorf("create output file: %w", err)}
	}
	return &atomicOutput{File: file, dest: dest}, nil
}

func (a *atomicOutput) discard() error {
	a.ready = false
	return a.Close()
}

func (a *atomicOutput) Close() error {
	name := a.Name()
	err := a.File.Close()
	if !a.ready {
		if removeErr := os.Remove(name); err == nil {
			err = removeErr
		}
		return err
	}
	if err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, a.dest); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("publish output file: %w", err)
	}
	return nil
}

// Handle is a sink and, for a path opened by SelectSink, its file.
type Handle struct {
	Sink
	close func() error
}

// Close closes a file opened by SelectSink. It is safe on stdout.
func (h *Handle) Close() error {
	if h == nil || h.close == nil {
		return nil
	}
	err := h.close()
	h.close = nil
	return err
}

// NewSink creates a sink for a local stdout or file writer.
func NewSink(format Format, target Target, writer io.Writer, options Options) (Sink, error) {
	if writer == nil {
		return nil, errors.New("output writer is nil")
	}
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	switch format {
	case FormatJSON, FormatJSONL, FormatSARIF, FormatText, FormatGHA, FormatMD:
		if target != TargetStdout && target != TargetFile {
			return nil, fmt.Errorf("output target %q: supported targets are stdout, file", target)
		}
	default:
		return nil, fmt.Errorf("output format %q: unsupported", format)
	}
	return &sink{format: format, writer: writer, options: options}, nil
}

// NewStdoutSink creates a sink for a human or CI output stream.
func NewStdoutSink(format Format, writer io.Writer, options Options) (Sink, error) {
	return NewSink(format, TargetStdout, writer, options)
}

// NewFileSink creates a sink for a local output file.
func NewFileSink(format Format, writer io.Writer, options Options) (Sink, error) {
	return NewSink(format, TargetFile, writer, options)
}

func validateOptions(options Options) error {
	if options.Redactor == nil {
		return errors.New("output: Options.Redactor is required; pass output.DefaultRedactor explicitly")
	}
	if _, err := sarifNonRepoMode(options); err != nil {
		return err
	}
	return nil
}

type sink struct {
	format   Format
	writer   io.Writer
	options  Options
	findings []model.Finding
	flushed  bool
}

func (s *sink) Write(finding model.Finding) error {
	if s.flushed {
		return errors.New("output sink is already flushed")
	}
	if err := finding.Validate(); err != nil {
		return fmt.Errorf("output finding: %w", err)
	}
	s.findings = append(s.findings, redactFinding(finding, s.options.Redactor))
	return nil
}

func (s *sink) Flush() error {
	if s.flushed {
		return errors.New("output sink is already flushed")
	}
	s.flushed = true
	findings := append([]model.Finding(nil), s.findings...)
	sortFindings(findings)
	presentFindings(findings)

	var err error
	switch s.format {
	case FormatJSON, FormatJSONL:
		err = renderJSONL(s.writer, findings, s.options)
	case FormatSARIF:
		err = renderSARIF(s.writer, findings, s.options)
	case FormatText:
		err = renderText(s.writer, findings, s.options)
	case FormatGHA:
		err = renderGHA(s.writer, findings, s.options)
	case FormatMD:
		err = renderMarkdown(s.writer, findings, s.options)
	default:
		err = fmt.Errorf("output format %q: unsupported", s.format)
	}
	if err != nil {
		return fmt.Errorf("write %s output: %w", s.format, err)
	}
	return nil
}

type sortItem struct {
	finding model.Finding
	encoded []byte
}

// sortFindings is a total order: the final key is the full JSON document,
// so two findings tie only when they are identical.
func sortFindings(findings []model.Finding) {
	items := make([]sortItem, len(findings))
	for i, finding := range findings {
		encoded, err := json.Marshal(finding)
		if err != nil {
			encoded = nil
		}
		items[i] = sortItem{finding: finding, encoded: encoded}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return compareFindings(items[i], items[j]) < 0
	})
	for i, item := range items {
		findings[i] = item.finding
	}
}

func compareFindings(left, right sortItem) int {
	a, b := left.finding, right.finding
	for _, compare := range []int{
		strings.Compare(a.Rule, b.Rule),
		strings.Compare(string(a.Location.Harness), string(b.Location.Harness)),
		strings.Compare(string(a.Location.Scope), string(b.Location.Scope)),
		strings.Compare(a.Location.Path, b.Location.Path),
		compareLine(a.Location.Line, b.Location.Line),
		compareSeverity(b.Severity, a.Severity),
		strings.Compare(string(a.Decision), string(b.Decision)),
		strings.Compare(a.Fingerprint, b.Fingerprint),
		strings.Compare(a.Title, b.Title),
		bytes.Compare(left.encoded, right.encoded),
	} {
		if compare != 0 {
			return compare
		}
	}
	return 0
}

func compareSeverity(left, right model.Severity) int {
	compare, err := left.Compare(right)
	if err != nil {
		return strings.Compare(string(left), string(right))
	}
	return compare
}

func compareLine(left, right *int) int {
	switch {
	case left == nil && right == nil:
		return 0
	case left == nil:
		return -1
	case right == nil:
		return 1
	case *left < *right:
		return -1
	case *left > *right:
		return 1
	default:
		return 0
	}
}

// Summarize counts findings by severity.
func Summarize(findings []model.Finding) Summary {
	summary := Summary{Findings: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case model.SeverityLow:
			summary.Low++
		case model.SeverityMedium:
			summary.Medium++
		case model.SeverityHigh:
			summary.High++
		case model.SeverityCritical:
			summary.Critical++
		}
	}
	return summary
}
