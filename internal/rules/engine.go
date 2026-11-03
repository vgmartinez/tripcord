package rules

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vgmartinez/tripcord/internal/advisory"
	"github.com/vgmartinez/tripcord/internal/hiddenchar"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/rules/argv"
	"github.com/vgmartinez/tripcord/internal/rules/mcppkg"
)

// Engine evaluates compiled rules against config items.
type Engine struct {
	env    *Env
	rules  []*Rule
	filter Filter
}

// Filter decides whether a rule that applies to an item runs on it.
// Policy supplies one, so the engine evaluates exactly the rules the
// effective policy enables.
type Filter func(r *Rule, item model.ConfigItem) bool

// Option configures an Engine.
type Option func(*Engine)

// WithFilter skips every rule and item pair that f rejects.
func WithFilter(f Filter) Option {
	return func(e *Engine) { e.filter = f }
}

// NewEngine returns an engine for rules, which must have been compiled
// in env.
func NewEngine(env *Env, rules []*Rule, opts ...Option) *Engine {
	e := &Engine{env: env, rules: append([]*Rule(nil), rules...)}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Match is a rule whose when expression was true for a config item.
// Severity is the per-match severity: the first true severity_when
// clause, or the rule severity when the rule has none.
type Match struct {
	Rule     *Rule
	Item     model.ConfigItem
	Severity model.Severity
	// Title is the matching clause's title, or empty for the rule title.
	Title string
	// Fix is the matching clause's fix, or empty for the rule fix.
	Fix string
	// Advisories are the embedded hits behind an evidence:advisory
	// match. The finding's excerpt, title, and refs are built from them.
	Advisories []advisory.Hit
}

// ConfigConfidence is the confidence of a config rule match. Config
// rules are deterministic expressions over the parsed file.
const ConfigConfidence = 1.0

// Finding builds the tripcord.finding/v1 record for m. Severity and
// decision come from the caller because policy overrides and mode
// decide them. The evidence cites the config item by ConfigItem.ID.
// When the payload carries a stable entry name, that name is the
// evidence key, so two matches in one file get distinct fingerprints.
// The evidence carries no file content. A rule with evidence
// hidden_chars adds an excerpt of the item's hidden code points by code
// point, line, and column (hiddenchar.Excerpt), and the first one's line
// to the location. For TC-CFG-011, the fingerprint uses the hidden-code
// point sequence and file identity, not those presentation coordinates.
func (m Match) Finding(severity model.Severity, decision model.Decision) (model.Finding, error) {
	id, err := m.Item.ID()
	if err != nil {
		return model.Finding{}, err
	}
	loc := model.Location{Harness: m.Item.Harness, Scope: m.Item.Scope, Path: m.Item.Path}
	entryKey := ConfigEvidenceKey(m.Item)
	evidence := []model.Evidence{{Config: &model.ConfigRef{ID: id, Key: entryKey}}}
	if hidden := m.Item.Hidden; m.Rule.Evidence == EvidenceHiddenChars && hidden.Total > 0 {
		evidence[0].Excerpt = hiddenchar.Excerpt(hidden)
		key := hiddenchar.FingerprintKey(hidden, 1)
		if m.Item.Harness == model.HarnessDevin && entryKey != "" {
			// Several Devin knowledge entries in one blueprint.yaml
			// share ID (one file) and, when their hidden runs are the
			// same code point, Sequence; overwriting entryKey below
			// would then collapse them onto one fingerprint. Devin's
			// entries already carry a content-derived key (see
			// kit.Source.AddDetect), so keep it instead of discarding
			// it. Every other harness keeps the plain
			// hiddenchar.FingerprintKey below, unchanged.
			key = entryKey + "/" + key
		}
		evidence[0].Config.Key = key
		if len(hidden.Runs) > 0 {
			line := hidden.Runs[0].Line
			loc.Line = &line
		}
	}
	if m.Rule.Evidence == EvidenceInstructionMatch {
		if line := instructionMatchLineItem(m.Item); line > 0 {
			loc.Line = &line
		}
	}
	title := cmp.Or(m.Title, m.Rule.Title)
	refs := append([]string(nil), m.Rule.Refs...)
	if m.Rule.Evidence == EvidenceAdvisory && len(m.Advisories) > 0 {
		evidence[0].Excerpt = advisory.Excerpt(m.Advisories)
		if m.Title == "" {
			title = advisory.Title(serverName(m.Item), m.Advisories)
		}
		refs = advisory.Refs(m.Rule.Refs, m.Advisories)
	}
	if loc.Line == nil && m.Item.Line > 0 {
		line := m.Item.Line
		loc.Line = &line
	}
	fp, err := model.Fingerprint(m.Rule.ID, loc, evidence)
	if err != nil {
		return model.Finding{}, err
	}
	f := model.Finding{
		Schema:      model.SchemaFinding,
		Rule:        m.Rule.ID,
		Title:       title,
		Severity:    severity,
		Decision:    decision,
		Confidence:  ConfigConfidence,
		Evidence:    evidence,
		Location:    loc,
		Refs:        refs,
		Fix:         cmp.Or(m.Fix, m.Rule.Fix),
		Fingerprint: fp,
	}
	if err := f.Validate(); err != nil {
		return model.Finding{}, err
	}
	return f, nil
}

// EvalError is a rule that could not be evaluated for an item. Rule is
// empty when the item itself was rejected, for example by a size limit.
type EvalError struct {
	Rule    string
	Harness model.Harness
	Scope   model.Scope
	Path    string
	Err     error
}

// Reason is a fixed description of Err for reports. It never includes
// the error text, which can quote values from the evaluated item.
func (e EvalError) Reason() string {
	switch {
	case errors.Is(e.Err, ErrCostLimit):
		return "cost limit exceeded"
	case errors.Is(e.Err, ErrTimeout):
		return "evaluation timed out"
	case errors.Is(e.Err, ErrBudget):
		return "evaluation budget exhausted"
	case errors.Is(e.Err, ErrInputLimit):
		return "input exceeds size limit"
	case errors.Is(e.Err, ErrNotBool):
		return "expression did not return a bool"
	case errors.Is(e.Err, ErrHookArgs):
		return ErrHookArgs.Error()
	case errors.Is(e.Err, context.Canceled), errors.Is(e.Err, context.DeadlineExceeded):
		return "scan cancelled"
	default:
		return "evaluation error"
	}
}

func (e EvalError) Error() string {
	if e.Rule == "" {
		return e.Path + ": " + e.Err.Error()
	}
	return e.Rule + ": " + e.Path + ": " + e.Err.Error()
}

// Result holds the matches and the evaluation failures of one scan.
// Failures are never reported as matches.
type Result struct {
	Matches []Match
	Errors  []EvalError
	Notices []EvalNotice
}

// EvalNotice reports an opaque config value that was excluded from a rule
// evaluation without making the scan incomplete.
type EvalNotice struct {
	Harness model.Harness
	Scope   model.Scope
	Path    string
	Pointer string
	Kind    NoticeKind
}

// NoticeKind describes an intentional normalization of an unreadable value.
type NoticeKind string

const (
	NoticeOpaqueMap   NoticeKind = "opaque_map"
	NoticeCoercedList NoticeKind = "coerced_list"
)

// ScanConfig evaluates every applicable rule against every item, in
// item order and then rule order. A rule applies when the item's
// harness is listed, its path matches one of the rule's globs, and the
// filter, if any, accepts it. The whole scan runs under the env's
// Budget; when the budget or ctx ends, the scan stops and records the
// cause for the next rule.
func (e *Engine) ScanConfig(ctx context.Context, items []model.ConfigItem) Result {
	ctx, cancel := e.env.Limits().WithBudget(ctx)
	defer cancel()
	var res Result
	for _, item := range items {
		var in *Input
		commandOpaque := opaqueCommand(item)
		if commandOpaque {
			res.Notices = append(res.Notices, EvalNotice{
				Harness: item.Harness,
				Scope:   item.Scope,
				Path:    item.Path,
				Pointer: "/command",
			})
		}
		res.Notices = append(res.Notices, argNotices(item)...)
		for _, r := range e.rules {
			if !r.Applies(item) || (e.filter != nil && !e.filter(r, item)) {
				continue
			}
			if ctx.Err() != nil {
				res.Errors = append(res.Errors, evalError(r.ID, item, ctxError(ctx)))
				return res
			}
			if in == nil {
				var err error
				in, err = ConfigInput(item, e.env.Limits())
				if err != nil {
					res.Errors = append(res.Errors, evalError("", item, err))
					break
				}
				if commandOpaque {
					break
				}
			}
			ok, err := r.When.Eval(ctx, in)
			if stopForEval(&res, r.ID, item, err) {
				continue
			}
			if !ok {
				continue
			}
			clause, matched, err := r.clauseFor(ctx, in)
			if stopForEval(&res, r.ID, item, err) {
				continue
			}
			if !matched {
				continue
			}
			match := Match{Rule: r, Item: item, Severity: clause.Severity, Title: clause.Title, Fix: clause.Fix}
			if r.Evidence == EvidenceAdvisory {
				hits, err := advisoryHits(in, e.env.Advisories())
				if stopForEval(&res, r.ID, item, err) {
					continue
				}
				match.Advisories = hits
			}
			res.Matches = append(res.Matches, match)
		}
	}
	return res
}

func advisoryHits(in *Input, db *advisory.DB) ([]advisory.Hit, error) {
	raw, _ := in.vars[VarPayload].(map[string]any)
	refs, _, err := mcppkg.ParsePayload(inputHarness(in), raw)
	if err != nil {
		return nil, fmt.Errorf("mcp: %w", ErrHookArgs)
	}
	if db == nil {
		return nil, nil
	}
	return db.Match(refs)
}

func serverName(item model.ConfigItem) string {
	var payload map[string]any
	if err := json.Unmarshal(item.Payload, &payload); err != nil {
		return "server"
	}
	if name, ok := payload["name"].(string); ok && strings.TrimSpace(name) != "" {
		return name
	}
	return "server"
}

func evalError(rule string, item model.ConfigItem, err error) EvalError {
	return EvalError{Rule: rule, Harness: item.Harness, Scope: item.Scope, Path: item.Path, Err: err}
}

// stopForEval reports whether evaluation of this rule should stop for item.
// Every evaluation error is recorded and stops the rule.
func stopForEval(res *Result, rule string, item model.ConfigItem, err error) bool {
	if err == nil {
		return false
	}
	res.Errors = append(res.Errors, evalError(rule, item, err))
	return true
}

// opaqueCommand reports a command value the selected agent cannot execute.
// An array is argv only for a harness whose schema accepts one. A number,
// bool, or object is never a command string, so it is opaque too.
func opaqueCommand(item model.ConfigItem) bool {
	if item.Kind != model.ConfigKindMCPServer {
		return false
	}
	var payload map[string]any
	if json.Unmarshal(item.Payload, &payload) != nil {
		return false
	}
	command, found := payload["command"]
	if !found || command == nil {
		return false
	}
	switch command.(type) {
	case string:
		return false
	case []any:
		return !mcppkg.AcceptsCommandArray(item.Harness)
	default:
		return true
	}
}

// argNotices reports map values excluded from matching and list values
// recursively coerced with JavaScript Array#toString semantics. Scalar
// siblings still participate in rule evaluation.
func argNotices(item model.ConfigItem) []EvalNotice {
	var payload map[string]any
	if json.Unmarshal(item.Payload, &payload) != nil {
		return nil
	}
	var notices []EvalNotice
	add := func(pointer string, value any) {
		_, kind := argv.Value(value, false)
		var noticeKind NoticeKind
		switch kind {
		case argv.OpaqueMap:
			noticeKind = NoticeOpaqueMap
		case argv.CoercedList:
			noticeKind = NoticeCoercedList
		default:
			return
		}
		notices = append(notices, EvalNotice{
			Harness: item.Harness,
			Scope:   item.Scope,
			Path:    item.Path,
			Pointer: pointer,
			Kind:    noticeKind,
		})
	}
	if args, ok := payload["args"].([]any); ok {
		for i, value := range args {
			add(fmt.Sprintf("/args/%d", i), value)
		}
	}
	if command, ok := payload["command"].([]any); ok && mcppkg.AcceptsCommandArray(item.Harness) {
		for i, value := range command {
			add(fmt.Sprintf("/command/%d", i), value)
		}
	}
	return notices
}
