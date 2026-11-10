package claude

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"

	"go.yaml.in/yaml/v3"
)

// splitFrontmatter returns the YAML frontmatter of a Markdown file. A UTF-8
// byte order mark is dropped and CRLF line endings are treated as LF, as
// Claude Code does, so neither can hide frontmatter hooks. The opening and
// opening delimiter may have trailing whitespace, matching Claude Code's
// /^---\s*\n/ parser. The close remains exact: Claude's lazy, non-line-
// anchored close can only make us emit extra findings, not miss hooks.
// An opening delimiter with no closing one is an error, so a truncated block
// fails closed.
func splitFrontmatter(raw []byte) (front []byte, found bool, err error) {
	text := bytes.TrimPrefix(raw, utf8BOM)
	text = bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n"))
	firstEnd := bytes.IndexByte(text, '\n')
	first := text
	if firstEnd >= 0 {
		first = text[:firstEnd]
	}
	if !bytes.Equal(bytes.TrimRight(first, " \t"), []byte("---")) {
		return nil, false, nil
	}
	if firstEnd < 0 {
		return nil, true, errors.New("frontmatter has no closing --- line")
	}
	rest := text[firstEnd+1:]
	offset := 0
	for offset <= len(rest) {
		end := bytes.IndexByte(rest[offset:], '\n')
		line := rest[offset:]
		if end >= 0 {
			line = rest[offset : offset+end]
		}
		if bytes.Equal(line, []byte("---")) {
			return rest[:offset], true, nil
		}
		if end < 0 {
			break
		}
		offset += end + 1
	}
	return nil, true, errors.New("frontmatter has no closing --- line")
}

// decodeYAML converts one YAML document into the same tree shape as
// decodeJSON. Aliases and merge keys are rejected so an alias bomb fails
// closed; nesting is bounded by maxNesting. Duplicate and case-variant keys
// are reported as warnings, with the last value used.
//
// A document whose only problem is a plain scalar YAML rejects (a
// description containing ": ", or an argument hint written `[a] [b]`)
// is read again with those scalars quoted. hooks and mcpServers, including
// a quoted key ("hooks", 'mcpServers', "mcp-servers"), are not rewritten:
// a value for one of them that is not valid YAML still fails closed,
// because that is the configuration a harness would execute.
func decodeYAML(raw []byte) (any, []string, error) {
	value, warnings, err := decodeYAMLDocument(raw)
	if err == nil || !yamlSyntaxError(err) {
		return value, warnings, err
	}
	repaired, ok := repairFrontmatterScalars(raw)
	if !ok {
		return nil, nil, err
	}
	value, warnings, err2 := decodeYAMLDocument(repaired)
	if err2 != nil {
		if yamlSyntaxError(err2) {
			return nil, nil, err
		}
		return nil, warnings, err2
	}
	return value, warnings, nil
}

func decodeYAMLDocument(raw []byte) (any, []string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Kind == 0 {
		return map[string]any{}, nil, nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, nil, errors.New("frontmatter is not one YAML document")
	}
	var warnings []string
	value, err := yamlValue(doc.Content[0], 0, "", &warnings)
	return value, warnings, err
}

func yamlValue(n *yaml.Node, depth int, where string, warnings *[]string) (any, error) {
	if depth >= maxNesting {
		return nil, fmt.Errorf("YAML nesting exceeds %d levels", maxNesting)
	}
	switch n.Kind {
	case yaml.AliasNode:
		return nil, errors.New("YAML aliases are not supported")
	case yaml.MappingNode:
		obj := map[string]any{}
		keys := newKeySet(where)
		for i := 0; i+1 < len(n.Content); i += 2 {
			keyNode, valueNode := n.Content[i], n.Content[i+1]
			if keyNode.Kind != yaml.ScalarNode {
				return nil, errors.New("YAML mapping key is not a scalar")
			}
			if keyNode.Tag == "!!merge" {
				return nil, errors.New("YAML merge keys are not supported")
			}
			value, err := yamlValue(valueNode, depth+1, joinWhere(where, keyNode.Value), warnings)
			if err != nil {
				return nil, err
			}
			*warnings = append(*warnings, keys.add(keyNode.Value)...)
			obj[keyNode.Value] = value
		}
		return obj, nil
	case yaml.SequenceNode:
		arr := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			value, err := yamlValue(item, depth+1, where+"[]", warnings)
			if err != nil {
				return nil, err
			}
			arr = append(arr, value)
		}
		return arr, nil
	case yaml.ScalarNode:
		return yamlScalar(n), nil
	default:
		return nil, fmt.Errorf("unsupported YAML node kind %d", n.Kind)
	}
}

func yamlScalar(n *yaml.Node) any {
	switch n.ShortTag() {
	case "!!null":
		return nil
	case "!!bool":
		var b bool
		if err := n.Decode(&b); err == nil {
			return b
		}
	case "!!int":
		var i int64
		if err := n.Decode(&i); err == nil {
			return i
		}
	case "!!float":
		var f float64
		if err := n.Decode(&f); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f
		}
	}
	return strings.Clone(n.Value)
}

// yamlSyntaxError reports an error from yaml.Unmarshal. Decoder errors
// (aliases, merge keys, nesting) are plain text and must not take the
// tolerant path.
func yamlSyntaxError(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "yaml:")
}

// securityFrontmatterKeys are the frontmatter fields a harness executes.
// A value for one of them that is not valid YAML is not quoted into a
// string: that would hide a hook or MCP server the strict parse refused.
// The lookup uses yamlMappingKey, so "hooks", 'hooks', and the same
// quoted forms of mcpServers and mcp-servers abort too.
var securityFrontmatterKeys = map[string]bool{
	"hooks":       true,
	"mcpServers":  true,
	"mcp-servers": true,
}

// yamlMappingKey strips one pair of matching YAML quotes from a mapping
// key. "hooks" and 'hooks' are then the same key as hooks.
func yamlMappingKey(key string) string {
	if len(key) >= 2 {
		q := key[0]
		if (q == '"' || q == '\'') && key[len(key)-1] == q {
			return key[1 : len(key)-1]
		}
	}
	return key
}

// repairFrontmatterScalars quotes plain scalar values that are not valid
// YAML on their own, which is how a lenient frontmatter reader keeps the
// rest of the document. It reports false when nothing can be repaired or
// when a security-relevant key would have to be rewritten.
func repairFrontmatterScalars(front []byte) ([]byte, bool) {
	lines := strings.Split(string(front), "\n")
	changed := false
	blockIndent := -1
	for i, line := range lines {
		if blockIndent >= 0 {
			if strings.TrimSpace(line) == "" || leadingSpaces(line) > blockIndent {
				continue
			}
			blockIndent = -1
		}
		next, did, block, abort := rewriteLooseScalar(line)
		if abort {
			return nil, false
		}
		if block >= 0 {
			blockIndent = block
		}
		if did {
			lines[i] = next
			changed = true
		}
	}
	if !changed {
		return nil, false
	}
	return []byte(strings.Join(lines, "\n")), true
}

func leadingSpaces(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// rewriteLooseScalar returns the line with its value double-quoted when
// the line is a mapping entry YAML itself rejects. block is the indent of
// a block scalar that follows, or -1. abort is set when the entry is a
// security-relevant key that cannot be parsed.
func rewriteLooseScalar(line string) (next string, changed bool, block int, abort bool) {
	block = -1
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || trimmed[0] == '#' {
		return line, false, block, false
	}
	indent := line[:leadingSpaces(line)]
	rest := line[len(indent):]
	dash := ""
	if strings.HasPrefix(rest, "- ") {
		dash = "- "
		rest = rest[len("- "):]
	}
	key, value, ok := strings.Cut(rest, ":")
	if !ok || key == "" || strings.TrimSpace(key) != key || strings.ContainsAny(key, " \t#{}[],&*!|>%@`") {
		return line, false, block, false
	}
	trim := strings.TrimSpace(value)
	if isBlockScalar(trim) {
		return line, false, leadingSpaces(line), false
	}
	if yamlLineOK(line) {
		return line, false, block, false
	}
	if securityFrontmatterKeys[yamlMappingKey(key)] {
		return line, false, block, true
	}
	if trim == "" {
		return line, false, block, false
	}
	return indent + dash + key + ": " + yamlDoubleQuote(trim), true, block, false
}

func isBlockScalar(value string) bool {
	if value == "" {
		return false
	}
	return value[0] == '|' || value[0] == '>'
}

func yamlLineOK(line string) bool {
	var doc yaml.Node
	return yaml.Unmarshal([]byte(line+"\n"), &doc) == nil
}

func yamlDoubleQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
