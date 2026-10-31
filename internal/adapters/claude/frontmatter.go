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
func decodeYAML(raw []byte) (any, []string, error) {
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
