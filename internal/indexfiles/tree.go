package indexfiles

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
)

var errOutside = errors.New("symlink resolves outside the tree")

type vnode struct {
	name   string
	path   string
	mode   string
	oid    string
	target string
	kids   map[string]*vnode
}

type fileTree struct {
	root   *vnode
	byPath map[string]*vnode
}

func buildTree(entries []Entry) (*fileTree, error) {
	t := &fileTree{
		root:   &vnode{name: ".", path: ".", mode: "dir", kids: map[string]*vnode{}},
		byPath: map[string]*vnode{},
	}
	for i := range entries {
		e := entries[i]
		if e.Path == "" || strings.HasPrefix(e.Path, "/") || strings.Contains(e.Path, "\\") {
			return nil, errors.New("index path is unsafe")
		}
		parts := strings.Split(e.Path, "/")
		cur := t.root
		for n, part := range parts {
			if part == "" || part == "." || part == ".." {
				return nil, errors.New("index path is unsafe")
			}
			last := n == len(parts)-1
			if cur.kids == nil {
				cur.kids = map[string]*vnode{}
			}
			child := cur.kids[part]
			if !last {
				if child == nil {
					child = &vnode{name: part, path: strings.Join(parts[:n+1], "/"), mode: "dir", kids: map[string]*vnode{}}
					cur.kids[part] = child
				}
				if child.mode != "dir" {
					return nil, errors.New("index path prefixes a file")
				}
				cur = child
				continue
			}
			mode := e.Mode
			switch mode {
			case "120000", "160000":
			case "100644", "100755", "100664", "":
				mode = "100644"
			default:
				return nil, errors.New("index path has an unknown mode")
			}
			node := &vnode{name: part, path: e.Path, mode: mode, oid: e.OID, target: e.Target}
			if mode == "160000" {
				node.kids = map[string]*vnode{}
			}
			cur.kids[part] = node
			t.byPath[e.Path] = node
		}
	}
	return t, nil
}

type hit struct {
	logical   string
	indexPath string
	links     []string
}

type walkLimit struct {
	maxDepth   int
	maxEntries int
}

func (t *fileTree) walk(candidate, relevant func(string) bool, lim walkLimit) (files []hit, links []string, reason string) {
	w := &walker{t: t, candidate: candidate, relevant: relevant, lim: lim, seen: map[*vnode]bool{}}
	if err := w.walk(".", 0, nil); err != nil {
		return nil, nil, ""
	}
	return w.files, w.links, w.reason
}

type walker struct {
	t         *fileTree
	candidate func(string) bool
	relevant  func(string) bool
	lim       walkLimit
	files     []hit
	links     []string
	entries   int
	reason    string
	seen      map[*vnode]bool
}

func (w *walker) truncate(reason string) {
	if w.reason == "" {
		w.reason = reason
	}
}

func (w *walker) walk(dir string, depth int, ancestors []*vnode) error {
	budget := w.lim.maxEntries - w.entries
	if budget <= 0 {
		w.truncate("too many directory entries")
		return nil
	}
	node, _, err := w.t.resolve(dir, 0)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(node.kids))
	for name := range node.kids {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > budget {
		names = names[:budget]
		w.truncate("too many directory entries")
	}
	w.entries += len(names)
	for _, name := range names {
		child := node.kids[name]
		rel := name
		if dir != "." {
			rel = dir + "/" + name
		}
		switch child.mode {
		case "120000":
			resolved, links, err := w.t.resolve(rel, 0)
			if err != nil || resolved == nil {
				if w.candidate(rel) || w.relevant(rel) {
					w.links = append(w.links, child.path)
				}
				continue
			}
			if resolved.mode == "dir" || resolved.mode == "160000" {
				w.links = append(w.links, links...)
				if err := w.descend(rel, name, depth, ancestors, resolved); err != nil {
					return err
				}
				continue
			}
			if w.candidate(rel) && resolved.mode == "100644" {
				w.files = append(w.files, hit{logical: rel, indexPath: resolved.path, links: append([]string{}, links...)})
			}
		case "dir", "160000":
			if err := w.descend(rel, name, depth, ancestors, child); err != nil {
				return err
			}
		default:
			if !w.candidate(rel) {
				continue
			}
			w.files = append(w.files, hit{logical: rel, indexPath: child.path})
		}
	}
	return nil
}

func (w *walker) descend(rel, name string, depth int, ancestors []*vnode, info *vnode) error {
	if name == ".git" {
		return nil
	}
	for _, ancestor := range ancestors {
		if ancestor == info {
			return nil
		}
	}
	if depth+1 > w.lim.maxDepth {
		w.truncate("directory nesting too deep")
		return nil
	}
	return w.walk(rel, depth+1, append(ancestors, info))
}

// resolve follows logical to a node. links are the symlink index paths
// followed. A target that leaves the tree returns errOutside.
func (t *fileTree) resolve(logical string, hops int) (*vnode, []string, error) {
	if hops > 40 {
		return nil, nil, fs.ErrInvalid
	}
	if logical == "" || logical == "." {
		return t.root, nil, nil
	}
	if logical == ".." || strings.HasPrefix(logical, "../") || strings.HasPrefix(logical, "/") {
		return nil, nil, errOutside
	}
	parts := strings.Split(logical, "/")
	cur := t.root
	var links []string
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, links, errOutside
		}
		if cur.kids == nil {
			return nil, links, fs.ErrNotExist
		}
		next := cur.kids[part]
		if next == nil {
			return nil, links, fs.ErrNotExist
		}
		if next.mode != "120000" {
			cur = next
			continue
		}
		links = append(links, next.path)
		dest, err := cleanTarget(strings.Join(parts[:i], "/"), next.target)
		if err != nil {
			return nil, links, err
		}
		rest := parts[i+1:]
		if len(rest) > 0 {
			if dest == "." {
				dest = strings.Join(rest, "/")
			} else {
				dest = dest + "/" + strings.Join(rest, "/")
			}
		}
		node, more, err := t.resolve(dest, hops+1)
		return node, append(links, more...), err
	}
	return cur, links, nil
}

func cleanTarget(dir, target string) (string, error) {
	target = strings.ReplaceAll(target, `\`, "/")
	if target == "" || strings.Contains(target, "\x00") {
		return "", fs.ErrInvalid
	}
	if strings.HasPrefix(target, "/") {
		return "", errOutside
	}
	base := dir
	if base == "." {
		base = ""
	}
	joined := target
	if base != "" {
		joined = base + "/" + target
	}
	cleaned := path.Clean(joined)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errOutside
	}
	return cleaned, nil
}
