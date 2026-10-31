// Package strictyaml decodes a single YAML document with unknown and
// duplicate keys rejected.
package strictyaml

import (
	"bytes"
	"errors"
	"io"

	"go.yaml.in/yaml/v3"
)

// Decode decodes exactly one YAML document from data into v.
func Decode(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty document")
		}
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("only one YAML document is allowed")
	}
	return nil
}
