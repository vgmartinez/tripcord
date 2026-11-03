package indexfiles

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/adapters/claude"
	"github.com/vgmartinez/tripcord/internal/adapters/codex"
	"github.com/vgmartinez/tripcord/internal/adapters/copilot"
	"github.com/vgmartinez/tripcord/internal/adapters/cursor"
	"github.com/vgmartinez/tripcord/internal/adapters/devcontainer"
	"github.com/vgmartinez/tripcord/internal/adapters/devin"
	"github.com/vgmartinez/tripcord/internal/adapters/gemini"
	"github.com/vgmartinez/tripcord/internal/adapters/generic"
	"github.com/vgmartinez/tripcord/internal/adapters/opencode"
	"github.com/vgmartinez/tripcord/internal/adapters/windsurf"
	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/policy"
)

// Entry is one git index record. Size is the blob size in bytes. Target
// is the symlink text when Mode is 120000. Body, when set, is the blob.
type Entry struct {
	Mode   string
	OID    string
	Path   string
	Size   int64
	Target string
	Body   []byte
}

// Write is one index path to place in the staged tree. Content fetches
// the blob. Sparse is the on-disk size when the blob is larger than a
// scan would read; the bytes are not written.
type Write struct {
	Mode    string
	OID     string
	Path    string
	Content bool
	Sparse  int64
}

// Plan is the staged tree a scan of this index would open.
type Plan struct {
	Writes []Write
	Notes  []adapters.Diagnostic
	// Sources maps a logical path (what an adapter reports as a
	// ConfigItem.Path) to every other logical path whose staged content
	// a finding at that path can depend on: the other side of its
	// symlink chain, and, for a Claude plugin manifest and the hook or
	// MCP files it names by path, every other member of that group. A
	// path with no such dependency has no entry.
	Sources map[string][]string
}

type walkerSpec struct {
	harness   model.Harness
	candidate func(string) bool
	relevant  func(string) bool
	claude    bool
}

func walkers() []walkerSpec {
	return []walkerSpec{
		{model.HarnessClaude, claude.WalkCandidate, claude.RepoRelevant, true},
		{model.HarnessCodex, codex.RepoCandidate, codex.RepoRelevant, false},
		{model.HarnessCopilot, copilot.RepoCandidate, copilot.RepoRelevant, false},
		{model.HarnessCursor, cursor.RepoCandidate, cursor.RepoRelevant, false},
		{model.SurfaceDevcontainer, devcontainer.RepoCandidate, devcontainer.RepoRelevant, false},
		{model.HarnessDevin, devin.RepoCandidate, devin.RepoRelevant, false},
		{model.HarnessGemini, gemini.RepoCandidate, gemini.RepoRelevant, false},
		{model.SurfaceGeneric, generic.RepoCandidate, generic.RepoRelevant, false},
		{model.HarnessOpenCode, opencode.RepoCandidate, opencode.RepoRelevant, false},
		{model.HarnessWindsurf, windsurf.RepoCandidate, windsurf.RepoRelevant, false},
	}
}

// Choose decides which index entries a repository scan would open.
// entries must carry Size and, for symlinks, Target. read loads a blob
// by oid when a policy or plugin manifest has to be parsed; it may be nil
// when those bodies are already on Entry.Body.
func Choose(entries []Entry, read func(oid string) ([]byte, error)) (Plan, error) {
	tree, err := buildTree(entries)
	if err != nil {
		return Plan{}, err
	}
	byPath := make(map[string]*Entry, len(entries))
	for i := range entries {
		byPath[entries[i].Path] = &entries[i]
	}
	writes := map[string]Write{}
	var notes []adapters.Diagnostic
	uf := newUnionFind()
	add := func(p string, content bool, sparse int64) {
		e := byPath[p]
		if e == nil || e.Mode == "160000" {
			return
		}
		prev, ok := writes[p]
		if ok && prev.Content {
			return
		}
		if ok && !content {
			return
		}
		mode := e.Mode
		if mode == "" {
			mode = "100644"
		}
		writes[p] = Write{Mode: mode, OID: e.OID, Path: p, Content: content, Sparse: sparse}
	}
	lim := walkLimit{maxDepth: maxDepth, maxEntries: maxEntries}
	for _, spec := range walkers() {
		files, links, reason := tree.walk(spec.candidate, spec.relevant, lim)
		if reason != "" {
			notes = append(notes, note(spec.harness, entryMessage(reason)))
		}
		for _, link := range links {
			add(link, true, 0)
		}
		var nfiles int
		var nbytes int64
		stop := func(why string) bool {
			if why == "" {
				return false
			}
			notes = append(notes, note(spec.harness, why))
			return true
		}
		if spec.claude {
			if why := consumeClaude(tree, files, byPath, read, add, uf, &nfiles, &nbytes); stop(why) {
				continue
			}
			continue
		}
		for _, h := range files {
			if why := consume(h, byPath, add, uf, &nfiles, &nbytes); why != "" {
				stop(why)
				break
			}
		}
	}
	addPolicy(tree, byPath, read, add)
	out := make([]Write, 0, len(writes))
	for _, w := range writes {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return Plan{Writes: out, Notes: notes, Sources: uf.groups()}, nil
}

func consume(h hit, byPath map[string]*Entry, add func(string, bool, int64), uf *unionFind, nfiles *int, nbytes *int64) string {
	uf.union(h.logical, h.indexPath)
	for _, link := range h.links {
		uf.union(h.logical, link)
		add(link, true, 0)
	}
	e := byPath[h.indexPath]
	if e == nil {
		return ""
	}
	keep, content, sparse, why := budget(e.Size, nfiles, nbytes)
	if !keep {
		return why
	}
	add(h.indexPath, content, sparse)
	return ""
}

// unionFind groups logical paths whose staged content are linked: the
// two ends of a symlink chain, or a plugin manifest and the hook or MCP
// files it names by path. groups returns, for every path in a group of
// two or more, every other member of that group.
type unionFind struct {
	parent map[string]string
}

func newUnionFind() *unionFind { return &unionFind{parent: map[string]string{}} }

func (u *unionFind) find(x string) string {
	if _, ok := u.parent[x]; !ok {
		u.parent[x] = x
		return x
	}
	for u.parent[x] != x {
		u.parent[x] = u.parent[u.parent[x]]
		x = u.parent[x]
	}
	return x
}

func (u *unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u.parent[ra] = rb
	}
}

func (u *unionFind) groups() map[string][]string {
	members := map[string][]string{}
	for x := range u.parent {
		root := u.find(x)
		members[root] = append(members[root], x)
	}
	out := map[string][]string{}
	for _, group := range members {
		if len(group) < 2 {
			continue
		}
		sort.Strings(group)
		for _, x := range group {
			out[x] = group
		}
	}
	return out
}

func budget(size int64, nfiles *int, nbytes *int64) (keep, content bool, sparse int64, why string) {
	if *nfiles >= maxFiles {
		return false, false, 0, filesMessage()
	}
	if size > maxFile {
		*nfiles++
		return true, false, size, ""
	}
	if size > maxBytes-*nbytes {
		return false, false, 0, bytesMessage()
	}
	*nfiles++
	*nbytes += size
	return true, true, 0, ""
}

func consumeClaude(tree *fileTree, files []hit, byPath map[string]*Entry, read func(string) ([]byte, error), add func(string, bool, int64), uf *unionFind, nfiles *int, nbytes *int64) string {
	roots := map[string]bool{}
	// rootManifests and rootMarkets record, for every known plugin root,
	// its own manifest path and every marketplace file that names it.
	// Every hooks.json, skill, agent, and command discovered under that
	// root "by convention" (see claude.RootFor) is unioned with both: a
	// commit that adds only the manifest or marketplace entry newly
	// makes an already-committed convention file into Claude
	// configuration, so a finding there can depend on the manifest's or
	// marketplace's staged content as much as its own.
	rootManifests := map[string]string{}
	rootMarkets := map[string][]string{}
	var markets, rest []hit
	for _, h := range files {
		if root, ok := claude.PluginRoot(h.logical); ok {
			roots[root] = true
			rootManifests[root] = h.logical
		}
		if claude.IsMarketplace(h.logical) {
			markets = append(markets, h)
			continue
		}
		rest = append(rest, h)
	}
	for _, h := range markets {
		if why := consume(h, byPath, add, uf, nfiles, nbytes); why != "" {
			return why
		}
		raw := blob(byPath[h.indexPath], read)
		if raw == nil {
			continue
		}
		for _, root := range claude.MarketplaceRoots(raw, h.logical) {
			roots[root] = true
			rootMarkets[root] = append(rootMarkets[root], h.logical)
		}
	}
	for _, h := range rest {
		if !claude.Reads(h.logical, roots) {
			continue
		}
		if why := consume(h, byPath, add, uf, nfiles, nbytes); why != "" {
			return why
		}
		if root, ok := claude.RootFor(h.logical, roots); ok {
			if manifest, ok := rootManifests[root]; ok {
				uf.union(h.logical, manifest)
			}
			for _, market := range rootMarkets[root] {
				uf.union(h.logical, market)
			}
		}
		if !claude.IsManifest(h.logical) {
			continue
		}
		raw := blob(byPath[h.indexPath], read)
		if raw == nil {
			continue
		}
		for _, ref := range claude.ManifestRefs(raw, h.logical) {
			// The manifest and every file it names by path form one
			// source-set group: a finding at any of them can depend on
			// the staged content of the others. This holds even when
			// ref does not resolve in the current index (resolved ==
			// nil below): a staged deletion of a manifest-referenced
			// hook or MCP file must still report a finding that
			// depended on it.
			uf.union(h.logical, ref)
			resolved, links, err := tree.resolve(ref, 0)
			if err != nil || resolved == nil || resolved.mode != "100644" {
				continue
			}
			if why := consume(hit{logical: ref, indexPath: resolved.path, links: links}, byPath, add, uf, nfiles, nbytes); why != "" {
				return why
			}
		}
	}
	return ""
}

func addPolicy(tree *fileTree, byPath map[string]*Entry, read func(string) ([]byte, error), add func(string, bool, int64)) {
	var seeds []string
	for p, e := range byPath {
		if !strings.HasPrefix(p, ".tripcord/") || e.Mode == "160000" {
			continue
		}
		place(tree, byPath, e, add)
		if p == ".tripcord/policy.yaml" {
			seeds = append(seeds, p)
		}
	}
	seen := map[string]bool{}
	pending := seeds
	for depth := 0; len(pending) > 0 && depth < policy.MaxExtendsDepth; depth++ {
		var next []string
		for _, p := range pending {
			if seen[p] {
				continue
			}
			seen[p] = true
			e := byPath[p]
			if e == nil || e.Size > policy.MaxFileBytes {
				continue
			}
			raw := blob(e, read)
			if len(raw) == 0 || len(raw) > policy.MaxFileBytes {
				continue
			}
			doc, err := policy.Parse(raw)
			if err != nil {
				continue
			}
			for _, ext := range doc.Extends {
				kind, _, err := policy.ParseExtends(string(ext))
				if err != nil || kind != policy.ExtendsPath {
					continue
				}
				joined, ok := joinInside(path.Dir(p), string(ext))
				if !ok {
					continue
				}
				target := byPath[joined]
				if target == nil {
					resolved, _, err := tree.resolve(joined, 0)
					if err != nil || resolved == nil {
						continue
					}
					target = byPath[resolved.path]
				}
				if target == nil {
					continue
				}
				place(tree, byPath, target, add)
				next = append(next, target.Path)
			}
		}
		pending = next
	}
}

func place(tree *fileTree, byPath map[string]*Entry, e *Entry, add func(string, bool, int64)) {
	if e.Mode == "120000" {
		add(e.Path, true, 0)
		resolved, links, err := tree.resolve(e.Path, 0)
		if err != nil || resolved == nil || resolved.mode != "100644" {
			return
		}
		for _, link := range links {
			add(link, true, 0)
		}
		if target := byPath[resolved.path]; target != nil {
			addSized(target.Path, target, add)
		}
		return
	}
	addSized(e.Path, e, add)
}

func addSized(p string, e *Entry, add func(string, bool, int64)) {
	limit := int64(policy.MaxFileBytes)
	if !strings.HasPrefix(p, ".tripcord/") {
		limit = maxFile
	}
	if e.Size > limit {
		add(p, false, e.Size)
		return
	}
	add(p, true, 0)
}

func blob(e *Entry, read func(string) ([]byte, error)) []byte {
	if e == nil {
		return nil
	}
	if e.Body != nil {
		return e.Body
	}
	if read == nil || e.OID == "" || e.Size > maxFile {
		return nil
	}
	body, err := read(e.OID)
	if err != nil {
		return nil
	}
	e.Body = body
	return body
}

func joinInside(dir, ref string) (string, bool) {
	ref = strings.ReplaceAll(ref, `\`, "/")
	if strings.HasPrefix(ref, "/") || strings.Contains(ref, "://") {
		return "", false
	}
	joined := path.Clean(path.Join(dir, ref))
	if joined == "." || joined == ".." || strings.HasPrefix(joined, "../") {
		return "", false
	}
	return joined, true
}

func note(h model.Harness, message string) adapters.Diagnostic {
	return adapters.Diagnostic{Harness: h, Scope: model.ScopeRepo, Message: message}
}

func entryMessage(reason string) string {
	return fmt.Sprintf("repository walk truncated: %s; configuration beyond the limit was not scanned", reason)
}

func filesMessage() string {
	return fmt.Sprintf("repository walk truncated: more than %d configuration files; the rest were not scanned", maxFiles)
}

func bytesMessage() string {
	return fmt.Sprintf("repository walk truncated: total configuration bytes exceed %d; the rest were not scanned", maxBytes)
}
