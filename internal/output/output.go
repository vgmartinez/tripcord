// Package output renders findings for people and CI integrations.
package output

import (
	"errors"
	"fmt"
	"io"
	"os"
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
	// SARIFNonRepoURIBase is the default. User and managed paths use a
	// relative artifact URI and uriBaseId USERHOME or MANAGED.
	SARIFNonRepoURIBase SARIFNonRepoLocation = "uri-base"
	// SARIFNonRepoLogical is the fallback for a code-scanning importer that
	// rejects or ignores uriBaseId-relative results. It emits logicalLocations
	// and keeps the normalized path in the result message.
	SARIFNonRepoLogical SARIFNonRepoLocation = "logical"
)

// DefaultSARIFNonRepoLocation is the representation used when Options does
// not select one. A real GitHub code scanning upload still has to confirm
// that the uriBaseId form is preserved.
const DefaultSARIFNonRepoLocation = SARIFNonRepoURIBase

// Target identifies the supported output destination.
type Target string

const (
	TargetStdout Target = "stdout"
	TargetFile   Target = "file"
)

// Options controls rendering without changing a finding document.
type Options struct {
	// RepoRoot makes an absolute repository path repository-relative when the
	// path is inside it. A repository path outside RepoRoot is omitted.
	RepoRoot string
	// NonRepoSARIF selects the SARIF form for user and managed paths.
	// The zero value uses DefaultSARIFNonRepoLocation.
	NonRepoSARIF SARIFNonRepoLocation
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
// text, sarif, gha, and md use the same path rule. There is no network sink.
// Close the returned handle when outputPath names a file.
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
	file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}
	sink, err := NewFileSink(format, file, options)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Handle{Sink: sink, close: file.Close}, nil
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
	if _, err := sarifNonRepoMode(options); err != nil {
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
	s.findings = append(s.findings, finding)
	return nil
}

func (s *sink) Flush() error {
	if s.flushed {
		return errors.New("output sink is already flushed")
	}
	s.flushed = true
	findings := append([]model.Finding(nil), s.findings...)
	sortFindings(findings)

	var err error
	switch s.format {
	case FormatJSON, FormatJSONL:
		err = renderJSONL(s.writer, findings)
	case FormatSARIF:
		err = renderSARIF(s.writer, findings, s.options)
	case FormatText:
		err = renderText(s.writer, findings)
	case FormatGHA:
		err = renderGHA(s.writer, findings, s.options)
	case FormatMD:
		err = renderMarkdown(s.writer, findings)
	default:
		err = fmt.Errorf("output format %q: unsupported", s.format)
	}
	if err != nil {
		return fmt.Errorf("write %s output: %w", s.format, err)
	}
	return nil
}

func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		for _, compare := range []int{
			strings.Compare(left.Rule, right.Rule),
			strings.Compare(string(left.Location.Harness), string(right.Location.Harness)),
			strings.Compare(left.Location.Path, right.Location.Path),
			compareLine(left.Location.Line, right.Location.Line),
			strings.Compare(left.Fingerprint, right.Fingerprint),
			strings.Compare(left.Title, right.Title),
		} {
			if compare != 0 {
				return compare < 0
			}
		}
		return false
	})
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
