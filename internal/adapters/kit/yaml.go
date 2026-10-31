package kit

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// SplitFrontmatter returns the YAML frontmatter of a Markdown file. A
// UTF-8 byte order mark is dropped and CRLF is treated as LF, so neither
// can hide frontmatter. Either delimiter may carry trailing whitespace. An
// opening delimiter without a closing one is an error.
func SplitFrontmatter(raw []byte) (front []byte, found bool, err error) {
	front, _, found, err = splitFrontmatter(raw)
	return front, found, err
}

// splitFrontmatter is SplitFrontmatter that also returns the Markdown body
// after the closing delimiter, with CRLF normalized to LF.
func splitFrontmatter(raw []byte) (front, body []byte, found bool, err error) {
	text := bytes.TrimPrefix(raw, utf8BOM)
	text = bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n"))
	firstEnd := bytes.IndexByte(text, '\n')
	first := text
	if firstEnd >= 0 {
		first = text[:firstEnd]
	}
	if !bytes.Equal(bytes.TrimRight(first, " \t"), []byte("---")) {
		return nil, nil, false, nil
	}
	if firstEnd < 0 {
		return nil, nil, true, errors.New("frontmatter has no closing --- line")
	}
	rest := text[firstEnd+1:]
	offset := 0
	for offset <= len(rest) {
		end := bytes.IndexByte(rest[offset:], '\n')
		line := rest[offset:]
		if end >= 0 {
			line = rest[offset : offset+end]
		}
		if bytes.Equal(bytes.TrimRight(line, " \t"), []byte("---")) {
			if end < 0 {
				return rest[:offset], nil, true, nil
			}
			return rest[:offset], rest[offset+end+1:], true, nil
		}
		if end < 0 {
			break
		}
		offset += end + 1
	}
	return nil, nil, true, errors.New("frontmatter has no closing --- line")
}

// AliasLimits bounds anchor/alias expansion in DecodeYAMLAliases: the
// number of alias nodes followed, and the number of nodes produced after
// expanding every alias. Both guard against an "alias bomb" (a handful of
// nested anchors that expand to an unbounded document, the "billion
// laughs" attack), while still allowing ordinary YAML that reuses a block
// with an anchor a few times. The zero value rejects any alias, the same
// as DecodeYAML.
type AliasLimits struct {
	MaxAliases int
	MaxNodes   int
}

// DecodeYAML converts one YAML document into the same tree shape as
// DecodeJSON. Aliases and merge keys are rejected so an alias bomb fails
// closed; nesting is bounded by MaxNesting. Duplicate and case-variant
// keys are reported, with the last value used. A UTF-8 byte order mark
// and CRLF line endings are accepted. folded is as for DecodeJSON.
func DecodeYAML(raw []byte, product string, folded ...string) (any, []string, error) {
	return decodeYAML(raw, product, AliasLimits{}, folded...)
}

// DecodeYAMLAliases is DecodeYAML, but permits anchors and aliases up to
// limits instead of rejecting every alias outright. Merge keys remain
// unsupported. A document whose alias count or expanded node count
// exceeds limits returns an error, so a short, well-formed file that
// expands exponentially still fails closed.
func DecodeYAMLAliases(raw []byte, product string, limits AliasLimits, folded ...string) (any, []string, error) {
	return decodeYAML(raw, product, limits, folded...)
}

func decodeYAML(raw []byte, product string, limits AliasLimits, folded ...string) (any, []string, error) {
	raw = bytes.TrimPrefix(raw, utf8BOM)
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Kind == 0 {
		return map[string]any{}, nil, nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, nil, errors.New("not one YAML document")
	}
	d := &yamlDecoder{product: product, folded: folded, limits: limits}
	value, err := d.value(doc.Content[0], 0, "")
	return value, d.warnings, err
}

type yamlDecoder struct {
	product    string
	folded     []string
	warnings   []string
	limits     AliasLimits
	aliasCount int
	nodeCount  int
}

func (d *yamlDecoder) value(n *yaml.Node, depth int, where string) (any, error) {
	if depth >= MaxNesting {
		return nil, fmt.Errorf("YAML nesting exceeds %d levels", MaxNesting)
	}
	d.nodeCount++
	if d.limits.MaxNodes > 0 && d.nodeCount > d.limits.MaxNodes {
		return nil, fmt.Errorf("YAML aliases expand to more than %d nodes", d.limits.MaxNodes)
	}
	switch n.Kind {
	case yaml.AliasNode:
		if d.limits.MaxAliases <= 0 {
			return nil, errors.New("YAML aliases are not supported")
		}
		d.aliasCount++
		if d.aliasCount > d.limits.MaxAliases {
			return nil, fmt.Errorf("YAML document has more than %d aliases", d.limits.MaxAliases)
		}
		return d.value(n.Alias, depth+1, where)
	case yaml.MappingNode:
		obj := map[string]any{}
		keys := NewKeySet(where, d.product)
		keys.foldOK = slices.Contains(d.folded, where)
		for i := 0; i+1 < len(n.Content); i += 2 {
			keyNode, valueNode := n.Content[i], n.Content[i+1]
			if keyNode.Kind != yaml.ScalarNode {
				return nil, errors.New("YAML mapping key is not a scalar")
			}
			if keyNode.Tag == "!!merge" {
				return nil, errors.New("YAML merge keys are not supported")
			}
			value, err := d.value(valueNode, depth+1, JoinWhere(where, keyNode.Value))
			if err != nil {
				return nil, err
			}
			d.warnings = append(d.warnings, keys.Add(keyNode.Value)...)
			obj[keyNode.Value] = value
		}
		return obj, nil
	case yaml.SequenceNode:
		arr := make([]any, 0, len(n.Content))
		for _, item := range n.Content {
			value, err := d.value(item, depth+1, where+"[]")
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

// ParseLooseFrontmatter parses "key: value" lines for frontmatter that is not
// valid YAML but that a harness still reads line by line, such as Cursor
// rules with an unquoted "globs: *.ts". Only top-level scalar lines are
// kept; values are strings.
func ParseLooseFrontmatter(front []byte) map[string]any {
	out := map[string]any{}
	for _, line := range strings.Split(string(front), "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return out
}
