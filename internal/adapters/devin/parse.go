package devin

import (
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/vgmartinez/tripcord/internal/adapters/kit"
	"github.com/vgmartinez/tripcord/internal/hiddenchar"
	"github.com/vgmartinez/tripcord/internal/model"
)

// file is one .devin/blueprint.yaml being normalized.
type file struct {
	*kit.Source
}

// blueprint normalizes initialize and maintenance, which run during a
// build, plus the maintenance text and knowledge entries the doc says
// are given to the agent at session start. Other keys are left alone.
// Devin accepts a multi-document YAML stream, same as a Kubernetes
// manifest: every "---"-separated document is read as part of the
// blueprint, not just the first.
func (f *file) blueprint(raw []byte) {
	docs, warnings, err := kit.DecodeYAMLDocuments(raw, product)
	f.WarnAll(warnings)
	if err != nil {
		f.Warn("invalid YAML: %v", err)
		return
	}
	if len(docs) == 0 {
		return
	}
	if _, valid := hiddenchar.Scan(raw); !valid {
		f.Warn("%s", kit.InvalidUTF8)
	}
	for _, doc := range docs {
		f.document(doc)
	}
}

// document normalizes one document of the blueprint stream.
func (f *file) document(doc kit.YAMLDocument) {
	obj, ok := doc.Value.(map[string]any)
	if !ok {
		f.Warn("blueprint must be a YAML mapping")
		return
	}
	for _, name := range []string{"initialize", "maintenance"} {
		value, present := obj[name]
		if !present {
			continue
		}
		f.section(name, value, mapValue(doc.Node, name))
	}
	if value, present := obj["knowledge"]; present {
		f.knowledge(value, mapValue(doc.Node, "knowledge"))
	}
}

// section emits one env-setup command per string, or per list entry.
// A list entry may be a string or a mapping with run and/or uses.
func (f *file) section(name string, value any, node *yaml.Node) {
	switch v := value.(type) {
	case string:
		f.command(name, "", v, valueLine(node), "string")
	case []any:
		f.commandList(name, v, node)
	default:
		f.Warn("%s must be a string or a list; it is reported as written", name)
		f.Add(model.ConfigKindEnvSetup, []string{"command", name}, map[string]any{
			"setting": name,
			"form":    "other",
			"value":   f.SafeValue(name, value),
		})
	}
}

func (f *file) commandList(name string, list []any, node *yaml.Node) {
	for i, item := range list {
		var elem *yaml.Node
		if node != nil && node.Kind == yaml.SequenceNode && i < len(node.Content) {
			elem = node.Content[i]
		}
		switch step := item.(type) {
		case string:
			f.command(name, "", step, valueLine(elem), "string")
		case map[string]any:
			f.step(name, step, elem)
		default:
			f.Warn("%s entry must be a string or a mapping; it is reported as written", name)
			f.Add(model.ConfigKindEnvSetup, []string{"command", name}, map[string]any{
				"setting": name,
				"form":    "other",
				"value":   f.SafeValue(name, item),
			})
		}
	}
}

// step emits a run command, a uses action, or both when a mapping
// carries them. uses is not a shell command.
func (f *file) step(section string, step map[string]any, node *yaml.Node) {
	name, _ := step["name"].(string)
	run, runString := step["run"].(string)
	if _, present := step["run"]; present && !runString {
		f.Warn("%s run must be a string; it is reported as written", section)
		f.Add(model.ConfigKindEnvSetup, []string{"command", section, name}, map[string]any{
			"setting": section,
			"name":    name,
			"form":    "other",
			"value":   f.SafeValue("run", step["run"]),
		})
	}
	if runString {
		f.command(section, name, run, valueLine(mapValue(node, "run")), "run")
	}
	uses, usesString := step["uses"].(string)
	if _, present := step["uses"]; present && !usesString {
		f.Warn("%s uses must be a string; it is reported as written", section)
	}
	if usesString {
		f.action(section, name, uses, step["with"], valueLine(mapValue(node, "uses")))
	}
	if _, runPresent := step["run"]; !runPresent {
		if _, usesPresent := step["uses"]; !usesPresent {
			f.Warn("%s entry has no run or uses", section)
		}
	}
}

func (f *file) command(section, name, command string, line int, form string) {
	if command == "" {
		return
	}
	payload := map[string]any{
		"setting": section,
		"form":    form,
		"command": f.SafeString(command),
	}
	if name != "" {
		payload["name"] = name
	}
	before := f.Len()
	f.AddDetect(model.ConfigKindEnvSetup, []string{"command", section, name}, payload, map[string]any{"command": command})
	f.MarkLine(before, line)
	// maintenance is surfaced to the agent at session start. initialize
	// is documented as build-only, so its text is not an instruction.
	if section == "maintenance" {
		f.instruction("maintenance", command, line)
	}
}

func (f *file) action(section, name, uses string, with any, line int) {
	payload := map[string]any{
		"setting": section,
		"form":    "uses",
		"uses":    f.SafeString(uses),
	}
	if name != "" {
		payload["name"] = name
	}
	if with != nil {
		payload["with"] = f.SafeValue("with", with)
	}
	before := f.Len()
	f.AddDetect(model.ConfigKindEnvSetup, []string{"uses", section, name}, payload, map[string]any{"uses": uses})
	f.MarkLine(before, line)
}

// knowledge emits each contents string. The doc loads these into
// Devin's context and does not execute them.
func (f *file) knowledge(value any, node *yaml.Node) {
	list, ok := value.([]any)
	if !ok {
		f.Warn("knowledge must be a list; it is reported as written")
		f.Add(model.ConfigKindEnvSetup, []string{"knowledge"}, map[string]any{
			"setting": "knowledge",
			"form":    "other",
			"value":   f.SafeValue("knowledge", value),
		})
		return
	}
	for i, item := range list {
		var elem *yaml.Node
		if node != nil && node.Kind == yaml.SequenceNode && i < len(node.Content) {
			elem = node.Content[i]
		}
		entry, ok := item.(map[string]any)
		if !ok {
			f.Warn("knowledge entry must be a mapping; it is reported as written")
			continue
		}
		text, ok := entry["contents"].(string)
		if !ok {
			if _, present := entry["contents"]; present {
				f.Warn("knowledge contents must be a string; it is reported as written")
			}
			continue
		}
		f.instruction("knowledge", text, valueLine(mapValue(elem, "contents")))
	}
}

// instruction records text the agent is shown. content keeps the
// command's place in the file so a match can name that line.
func (f *file) instruction(role, text string, line int) {
	if strings.TrimSpace(text) == "" {
		return
	}
	raw := text
	if line > 1 {
		raw = strings.Repeat("\n", line-1) + text
	}
	before := f.Len()
	f.AddDetect(model.ConfigKindInstructions, []string{role}, map[string]any{
		"role":    role,
		"content": f.SafeString(text),
	}, map[string]any{"content": raw}, "role")
	f.MarkLine(before, line)
	hidden, _ := hiddenchar.Scan([]byte(raw))
	f.MarkHidden(before, hidden)
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	var found *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			found = m.Content[i+1]
		}
	}
	return found
}

// valueLine is the 1-based line of a scalar. A block scalar's node line
// is the "|" or ">" indicator; the text starts on the next line.
func valueLine(n *yaml.Node) int {
	if n == nil || n.Line < 1 {
		return 0
	}
	if n.Kind == yaml.ScalarNode && n.Value != "" && n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return n.Line + 1
	}
	return n.Line
}
