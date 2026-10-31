package claude

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/model"
)

// readClaudeJSON streams ~/.claude.json and keeps only "mcpServers" and
// "projects.<path>.mcpServers"; everything else is skipped token by token.
func readClaudeJSON(c *collector, home, abs, logical string) {
	file, err := adapters.OpenLocal(abs)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		c.warn(model.ScopeUser, logical, "cannot read: %v", err)
		return
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	limited := &io.LimitedReader{R: file, N: maxClaudeJSONBytes + 1}
	tee := io.TeeReader(limited, hash)
	servers, warnings, err := parseClaudeJSON(tee, home)
	if err == nil {
		_, err = io.Copy(io.Discard, tee)
	}
	if err == nil && limited.N == 0 {
		err = fmt.Errorf("exceeds %d byte limit", maxClaudeJSONBytes)
	}
	s := &src{c: c, scope: model.ScopeUser, path: logical, sha: hex.EncodeToString(hash.Sum(nil))}
	s.warnAll(warnings)
	if err != nil {
		s.warn("invalid or unreadable: %v", err)
		return
	}
	projects := make([]string, 0, len(servers))
	for project := range servers {
		projects = append(projects, project)
	}
	sort.Strings(projects)
	for _, project := range projects {
		s.mcpServers(servers[project], project)
	}
}

// parseClaudeJSON returns the MCP server objects keyed by project ("" for
// the top level). Project keys under home are rewritten as "~/...".
func parseClaudeJSON(r io.Reader, home string) (map[string]any, []string, error) {
	br := bufio.NewReader(r)
	if head, err := br.Peek(len(utf8BOM)); err == nil && bytes.Equal(head, utf8BOM) {
		return nil, nil, errors.New("JSON starts with a byte order mark")
	}
	dec := json.NewDecoder(br)
	dec.UseNumber()
	t := &treeDecoder{dec: dec}
	servers := map[string]any{}
	if err := expectDelim(dec, '{'); err != nil {
		return nil, nil, err
	}
	top := newKeySet("")
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, t.warnings, err
		}
		t.warnings = append(t.warnings, top.add(key)...)
		switch key {
		case "mcpServers":
			value, err := t.value(1, key)
			if err != nil {
				return nil, t.warnings, err
			}
			servers[""] = value
		case "projects":
			if err := t.projects(home, servers); err != nil {
				return nil, t.warnings, err
			}
		default:
			if err := t.skip(); err != nil {
				return nil, t.warnings, err
			}
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, t.warnings, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, t.warnings, errors.New("more than one JSON value")
		}
		return nil, t.warnings, err
	}
	return servers, t.warnings, nil
}

func (t *treeDecoder) projects(home string, servers map[string]any) error {
	tok, err := t.dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		_, err := t.fromToken(tok, 1, "projects")
		return err
	}
	projects := newKeySet("projects")
	for t.dec.More() {
		project, err := objectKey(t.dec)
		if err != nil {
			return err
		}
		t.warnings = append(t.warnings, projects.add(project)...)
		tok, err := t.dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := tok.(json.Delim); !ok || delim != '{' {
			if _, err := t.fromToken(tok, 2, "projects"); err != nil {
				return err
			}
			continue
		}
		keys := newKeySet("projects entry")
		for t.dec.More() {
			key, err := objectKey(t.dec)
			if err != nil {
				return err
			}
			t.warnings = append(t.warnings, keys.add(key)...)
			if key != "mcpServers" {
				if err := t.skip(); err != nil {
					return err
				}
				continue
			}
			value, err := t.value(3, "projects.mcpServers")
			if err != nil {
				return err
			}
			servers[tildePath(home, project)] = value
		}
		if err := expectDelim(t.dec, '}'); err != nil {
			return err
		}
	}
	return expectDelim(t.dec, '}')
}

func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", errors.New("object key is not a string")
	}
	return key, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != want {
		return fmt.Errorf("expected %q", want)
	}
	return nil
}
