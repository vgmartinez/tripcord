package embedded

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// errConflict marks a merge that is only possible with --force.
var errConflict = errors.New("conflict")

// conflictf is a merge that --force may override.
func conflictf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errConflict, fmt.Sprintf(format, args...))
}

// unmergeable is a merge that --force does not override: the file
// cannot be parsed, or has a shape Tripcord would have to discard.
type unmergeable struct{ reason string }

func (e *unmergeable) Error() string { return e.reason }

func unmergeablef(format string, args ...any) error {
	return &unmergeable{reason: fmt.Sprintf(format, args...)}
}

// ownFile is a file only Tripcord writes: it must equal want.
func ownFile(old []byte, exists bool, want []byte, force bool, hint string) ([]byte, error) {
	if !exists || bytes.Equal(old, want) || force {
		return want, nil
	}
	return nil, conflictf("the file differs from what init writes; %s", hint)
}

// hookFile describes a JSON file of hook arrays keyed by event.
type hookFile struct {
	// version, when set, is the "version": 1 member Cursor and Copilot
	// hook files carry.
	version bool
	// disableKey, when set, is a member that turns every hook in the
	// file off when true.
	disableKey string
}

func mergeHooks(old []byte, exists bool, entries []HookEntry, f hookFile, force bool) ([]byte, error) {
	var doc *jsonDoc
	if exists {
		var err error
		doc, err = readJSONDoc(old)
		if err != nil {
			return nil, unmergeablef("cannot parse as JSON: %v", err)
		}
		if !doc.stable && !force {
			return nil, conflictf("merging would reformat the file (Tripcord rewrites JSON with %q indentation and no comments)", doc.indent)
		}
	} else {
		doc = &jsonDoc{root: object(), indent: "  "}
		if f.version {
			doc.root.set("version", toNode(1))
		}
	}
	root := doc.root
	if f.version {
		switch v := root.get("version"); {
		case v == nil:
			root.set("version", toNode(1))
		case v.kind != kindScalar || string(v.raw) != "1":
			return nil, unmergeablef(`"version" is %s; Tripcord writes version 1 hooks`, v.canonical())
		}
	}
	if f.disableKey != "" {
		if v := root.get(f.disableKey); v != nil && string(v.raw) == "true" && !force {
			return nil, conflictf("%s is true, so the Tripcord hooks would never run", f.disableKey)
		}
	}
	hooks := root.get("hooks")
	if hooks == nil {
		hooks = object()
		root.set("hooks", hooks)
	}
	if hooks.kind != kindObject {
		return nil, unmergeablef(`"hooks" is not an object`)
	}
	for _, e := range entries {
		list := hooks.get(e.Event)
		if list == nil {
			list = array()
			hooks.set(e.Event, list)
		}
		if list.kind != kindArray {
			return nil, unmergeablef(`"hooks.%s" is not an array`, e.Event)
		}
		if err := placeEntry(list, e, force); err != nil {
			return nil, err
		}
	}
	return doc.root.encode(doc.indent), nil
}

// placeEntry adds e.entry to list unless an identical entry is there.
// An entry that names tripcord but differs is someone's edit of a
// Tripcord hook, or their own Tripcord hook: --force replaces it.
func placeEntry(list *node, e HookEntry, force bool) error {
	for _, item := range list.items {
		if item.equal(e.entry) {
			return nil
		}
	}
	for i, item := range list.items {
		if namesTripcord(item) {
			if !force {
				return conflictf("hooks.%s already has a Tripcord hook that differs from what init writes", e.Event)
			}
			list.items[i] = e.entry
			return nil
		}
	}
	list.items = append(list.items, e.entry)
	return nil
}

// mergeCursorEnvironment sets install in .cursor/environment.json.
func mergeCursorEnvironment(old []byte, exists bool, force bool) ([]byte, error) {
	if !exists {
		return object("install", installCommand).encode("  "), nil
	}
	doc, err := readJSONDoc(old)
	if err != nil {
		return nil, unmergeablef("cannot parse as JSON: %v", err)
	}
	if !doc.stable && !force {
		return nil, conflictf("merging would reformat the file (Tripcord rewrites JSON with %q indentation and no comments)", doc.indent)
	}
	install := doc.root.get("install")
	if install == nil {
		doc.root.set("install", toNode(installCommand))
		return doc.root.encode(doc.indent), nil
	}
	current, ok := install.str()
	switch {
	case !ok:
		return nil, unmergeablef(`"install" is not a string`)
	case current == installCommand || strings.HasPrefix(current, installCommand+" && "):
	case !force:
		return nil, conflictf(`"install" is already set; --force runs Tripcord's bootstrap first, then the existing command`)
	default:
		doc.root.set("install", toNode(installCommand+" && "+current))
	}
	return doc.root.encode(doc.indent), nil
}

// mergeAgents adds or refreshes the marked note in AGENTS.md.
func mergeAgents(old []byte, exists bool, force bool) ([]byte, error) {
	note := agentsNote()
	if !exists || len(bytes.TrimSpace(old)) == 0 {
		return []byte(note), nil
	}
	text := string(old)
	begin := strings.Index(text, agentsBegin)
	if begin < 0 {
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		return []byte(text + "\n" + note), nil
	}
	rel := strings.Index(text[begin:], agentsEnd)
	if rel < 0 {
		return nil, unmergeablef("%s has no matching %s", agentsBegin, agentsEnd)
	}
	end := begin + rel + len(agentsEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	if text[begin:end] == note {
		return old, nil
	}
	if !force {
		return nil, conflictf("the Tripcord note differs from what init writes")
	}
	return []byte(text[:begin] + note + text[end:]), nil
}

// yamlDoc is an existing YAML file parsed for a merge; see jsonDoc.
type yamlDoc struct {
	root   *yaml.Node
	stable bool
}

func readYAMLDoc(raw []byte) (*yamlDoc, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("not one YAML mapping")
	}
	out, err := encodeYAML(&doc)
	if err != nil {
		return nil, err
	}
	return &yamlDoc{root: &doc, stable: bytes.Equal(out, raw)}, nil
}

func encodeYAML(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func runStep(name string) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		scalar("name"), scalar(name),
		scalar("run"), scalar(installCommand),
	}}
}

// mergeSetupSteps appends the bootstrap step to the copilot-setup-steps
// job.
func mergeSetupSteps(old []byte, exists bool, force bool) ([]byte, error) {
	if !exists {
		return CopilotSetupSteps(), nil
	}
	doc, err := readYAMLDoc(old)
	if err != nil {
		return nil, unmergeablef("cannot parse as YAML: %v", err)
	}
	steps := mapValue(mapValue(mapValue(doc.root.Content[0], "jobs"), "copilot-setup-steps"), "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return nil, unmergeablef("no jobs.copilot-setup-steps.steps list")
	}
	checkout := false
	for _, step := range steps.Content {
		run := mapValue(step, "run")
		if run != nil && strings.TrimSpace(run.Value) == installCommand {
			return old, nil
		}
		if uses := mapValue(step, "uses"); uses != nil && strings.HasPrefix(uses.Value, "actions/checkout@") {
			checkout = true
		}
	}
	for _, step := range steps.Content {
		if run := mapValue(step, "run"); run != nil && containsFold(run.Value, "tripcord") {
			if !force {
				return nil, conflictf("a step already runs Tripcord with a different command")
			}
			run.Value = installCommand
			return encodeYAML(doc.root)
		}
	}
	if !checkout && !force {
		return nil, conflictf("no actions/checkout step, so %s would not be in the workspace", BootstrapPath)
	}
	if !doc.stable && !force {
		return nil, conflictf("merging would reformat the file (Tripcord rewrites YAML with 2-space indentation)")
	}
	steps.Content = append(steps.Content, runStep(copilotStepName))
	return encodeYAML(doc.root)
}

// mergeBlueprint appends the bootstrap command to the Devin blueprint's
// maintenance section.
func mergeBlueprint(old []byte, exists bool, force bool) ([]byte, error) {
	if !exists {
		return DevinBlueprint(), nil
	}
	doc, err := readYAMLDoc(old)
	if err != nil {
		return nil, unmergeablef("cannot parse as YAML: %v", err)
	}
	top := doc.root.Content[0]
	maintenance := mapValue(top, "maintenance")
	if maintenance != nil && maintenance.Kind == yaml.SequenceNode {
		for _, entry := range maintenance.Content {
			if strings.TrimSpace(entry.Value) == installCommand {
				return old, nil
			}
			if run := mapValue(entry, "run"); run != nil && strings.TrimSpace(run.Value) == installCommand {
				return old, nil
			}
		}
	}
	if !doc.stable && !force {
		return nil, conflictf("merging would reformat the file (Tripcord rewrites YAML with 2-space indentation)")
	}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		scalar("name"), scalar("tripcord"),
		scalar("run"), scalar(installCommand),
	}}
	switch {
	case maintenance == nil:
		top.Content = append(top.Content, scalar("maintenance"),
			&yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{entry}})
	case maintenance.Kind == yaml.SequenceNode:
		maintenance.Content = append(maintenance.Content, entry)
	case maintenance.Kind == yaml.ScalarNode && force:
		prior := *maintenance
		*maintenance = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{&prior, entry}}
	case maintenance.Kind == yaml.ScalarNode:
		return nil, conflictf("maintenance is one command; --force turns it into a list and adds Tripcord's")
	default:
		return nil, unmergeablef("maintenance is not a command or a list")
	}
	return encodeYAML(doc.root)
}

// namesTripcord reports whether any string in n mentions tripcord, the
// sign of a Tripcord hook that someone edited.
func namesTripcord(n *node) bool {
	if s, ok := n.str(); ok {
		return containsFold(s, "tripcord")
	}
	return slices.ContainsFunc(n.items, namesTripcord)
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), sub)
}
