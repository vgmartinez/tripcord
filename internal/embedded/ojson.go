package embedded

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// node is a JSON value that keeps object key order, so a merged file
// re-encodes with the user's keys where they were.
type node struct {
	kind  nodeKind
	keys  []string
	items []*node
	// raw is a scalar's compact encoding.
	raw []byte
}

type nodeKind int

const (
	kindScalar nodeKind = iota
	kindObject
	kindArray
)

const maxNodeDepth = 64

func object(pairs ...any) *node {
	n := &node{kind: kindObject}
	for i := 0; i+1 < len(pairs); i += 2 {
		n.set(pairs[i].(string), toNode(pairs[i+1]))
	}
	return n
}

// digest is the SHA-256 of n's canonical JSON.
func (n *node) digest() string { return digest(n.canonical()) }

func array(items ...any) *node {
	n := &node{kind: kindArray}
	for _, item := range items {
		n.items = append(n.items, toNode(item))
	}
	return n
}

func toNode(v any) *node {
	if n, ok := v.(*node); ok {
		return n
	}
	raw, err := marshalScalar(v)
	if err != nil {
		panic(err)
	}
	return &node{kind: kindScalar, raw: raw}
}

func marshalScalar(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// get returns the member key of an object, or nil.
func (n *node) get(key string) *node {
	if n == nil || n.kind != kindObject {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.items[i]
		}
	}
	return nil
}

// set replaces member key, or appends it after the existing members.
func (n *node) set(key string, v *node) {
	for i, k := range n.keys {
		if k == key {
			n.items[i] = v
			return
		}
	}
	n.keys = append(n.keys, key)
	n.items = append(n.items, v)
}

// str returns a string scalar's value.
func (n *node) str() (string, bool) {
	if n == nil || n.kind != kindScalar || len(n.raw) == 0 || n.raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(n.raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// canonical is n with object keys sorted and no whitespace: two values
// that a harness reads the same way have the same canonical form.
func (n *node) canonical() []byte {
	var buf bytes.Buffer
	n.writeCanonical(&buf)
	return buf.Bytes()
}

func (n *node) writeCanonical(buf *bytes.Buffer) {
	switch n.kind {
	case kindScalar:
		buf.Write(n.raw)
	case kindArray:
		buf.WriteByte('[')
		for i, item := range n.items {
			if i > 0 {
				buf.WriteByte(',')
			}
			item.writeCanonical(buf)
		}
		buf.WriteByte(']')
	case kindObject:
		order := make([]int, len(n.keys))
		for i := range order {
			order[i] = i
		}
		sort.Slice(order, func(a, b int) bool { return n.keys[order[a]] < n.keys[order[b]] })
		buf.WriteByte('{')
		for i, idx := range order {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, _ := marshalScalar(n.keys[idx])
			buf.Write(key)
			buf.WriteByte(':')
			n.items[idx].writeCanonical(buf)
		}
		buf.WriteByte('}')
	default:
		panic("unhandled node kind")
	}
}

func (n *node) equal(o *node) bool {
	return o != nil && bytes.Equal(n.canonical(), o.canonical())
}

// parseJSON decodes one strict JSON document. A duplicate key is an
// error: which copy a harness reads is not something a merge can keep.
func parseJSON(raw []byte) (*node, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	n, err := decodeNode(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value")
	}
	return n, nil
}

func decodeNode(dec *json.Decoder, depth int) (*node, error) {
	if depth > maxNodeDepth {
		return nil, errors.New("JSON nests too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			n := &node{kind: kindObject}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if n.get(key) != nil {
					return nil, fmt.Errorf("duplicate key %q", key)
				}
				child, err := decodeNode(dec, depth+1)
				if err != nil {
					return nil, err
				}
				n.keys = append(n.keys, key)
				n.items = append(n.items, child)
			}
			_, err := dec.Token()
			return n, err
		case '[':
			n := &node{kind: kindArray}
			for dec.More() {
				child, err := decodeNode(dec, depth+1)
				if err != nil {
					return nil, err
				}
				n.items = append(n.items, child)
			}
			_, err := dec.Token()
			return n, err
		default:
			return nil, fmt.Errorf("unexpected %q", t)
		}
	case json.Number:
		return &node{kind: kindScalar, raw: []byte(t.String())}, nil
	default:
		raw, err := marshalScalar(t)
		if err != nil {
			return nil, err
		}
		return &node{kind: kindScalar, raw: raw}, nil
	}
}

// encode writes n with indent per level and a trailing newline.
func (n *node) encode(indent string) []byte {
	var buf bytes.Buffer
	n.writeIndented(&buf, indent, 0)
	buf.WriteByte('\n')
	return buf.Bytes()
}

func (n *node) writeIndented(buf *bytes.Buffer, indent string, level int) {
	pad := func(l int) { buf.WriteString(strings.Repeat(indent, l)) }
	switch n.kind {
	case kindScalar:
		buf.Write(n.raw)
	case kindArray:
		if len(n.items) == 0 {
			buf.WriteString("[]")
			return
		}
		buf.WriteString("[\n")
		for i, item := range n.items {
			pad(level + 1)
			item.writeIndented(buf, indent, level+1)
			if i < len(n.items)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		pad(level)
		buf.WriteByte(']')
	case kindObject:
		if len(n.keys) == 0 {
			buf.WriteString("{}")
			return
		}
		buf.WriteString("{\n")
		for i, key := range n.keys {
			pad(level + 1)
			k, _ := marshalScalar(key)
			buf.Write(k)
			buf.WriteString(": ")
			n.items[i].writeIndented(buf, indent, level+1)
			if i < len(n.keys)-1 {
				buf.WriteByte(',')
			}
			buf.WriteByte('\n')
		}
		pad(level)
		buf.WriteByte('}')
	default:
		panic("unhandled node kind")
	}
}

// detectIndent returns the leading whitespace of the first indented
// line of raw, or two spaces.
func detectIndent(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed != "" && len(trimmed) < len(line) {
			return line[:len(line)-len(trimmed)]
		}
	}
	return "  "
}

// jsonDoc is an existing JSON file parsed for a merge. stable reports
// whether re-encoding the unmodified document reproduces the file byte
// for byte; when it does not, a merge would reformat the user's file.
type jsonDoc struct {
	root   *node
	indent string
	stable bool
}

func readJSONDoc(raw []byte) (*jsonDoc, error) {
	root, err := parseJSON(raw)
	if err != nil {
		return nil, err
	}
	if root.kind != kindObject {
		return nil, errors.New("top level is not a JSON object")
	}
	indent := detectIndent(raw)
	return &jsonDoc{root: root, indent: indent, stable: bytes.Equal(root.encode(indent), raw)}, nil
}
