package indexfiles

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/vgmartinez/tripcord/internal/adapters"
	"github.com/vgmartinez/tripcord/internal/preopen"
)

// Materialize writes the index paths a repository scan would open into a
// private tree. Gitlinks are not blobs. Files the index does not contain
// are left missing. The returned sources map is Plan.Sources: it names,
// for a logical path a scan would report, the other paths a finding
// there can depend on (see Plan.Sources).
// indexFile, when set, is the index git is building for a commit
// currently in a hook (see gitrun.IndexEnv), so the scan reads the
// proposed commit's content rather than the stale on-disk .git/index.
func Materialize(ctx context.Context, repo, indexFile string) (*preopen.Workspace, []adapters.Diagnostic, map[string][]string, error) {
	objs, gitDir, err := preopen.ListIndex(ctx, repo, indexFile)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(objs) == 0 {
		return nil, nil, nil, errEmptyIndex
	}
	entries := make([]Entry, len(objs))
	var blobs, links []string
	for i, obj := range objs {
		entries[i] = Entry{Mode: obj.Mode, OID: obj.OID, Path: obj.Path, Size: obj.Size}
		switch obj.Mode {
		case "120000":
			links = append(links, obj.OID)
		case "160000":
		default:
			blobs = append(blobs, obj.OID)
		}
	}
	sizes, err := preopen.BlobSizes(ctx, gitDir, unique(blobs))
	if err != nil {
		return nil, nil, nil, err
	}
	linkSizes, err := preopen.BlobSizes(ctx, gitDir, unique(links))
	if err != nil {
		return nil, nil, nil, err
	}
	var linkRead []string
	for oid, size := range linkSizes {
		if size <= maxSymlinkBytes {
			linkRead = append(linkRead, oid)
		}
	}
	linkBody, err := preopen.ReadBlobs(ctx, gitDir, linkRead)
	if err != nil {
		return nil, nil, nil, err
	}
	for i := range entries {
		if s, ok := sizes[entries[i].OID]; ok && entries[i].Mode != "120000" {
			entries[i].Size = s
		}
		if entries[i].Mode == "120000" {
			entries[i].Size = linkSizes[entries[i].OID]
			if body, ok := linkBody[entries[i].OID]; ok {
				entries[i].Target = string(body)
			}
		}
		objs[i].Size = entries[i].Size
		objs[i].Target = entries[i].Target
	}
	plan, err := Choose(entries, func(oid string) ([]byte, error) {
		got, err := preopen.ReadBlobs(ctx, gitDir, []string{oid})
		if err != nil {
			return nil, err
		}
		return got[oid], nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	ws, err := preopen.NewStagedTree(objs, gitDir)
	if err != nil {
		return nil, nil, nil, err
	}
	put := make([]preopen.IndexObject, len(plan.Writes))
	for i, w := range plan.Writes {
		put[i] = preopen.IndexObject{Mode: w.Mode, OID: w.OID, Path: w.Path, Kind: "blob", Sparse: w.Sparse}
		if w.Mode == "160000" {
			put[i].Kind = "commit"
		}
	}
	if err := ws.Put(ctx, put); err != nil {
		_ = ws.Close()
		return nil, nil, nil, err
	}
	return ws, plan.Notes, plan.Sources, nil
}

// AddReferences writes index paths that rules follow from items already
// discovered: hook scripts, checksum files, and symlink targets inside
// the tree. A path that is not in the index is left missing.
func AddReferences(ctx context.Context, ws *preopen.Workspace, paths []string) error {
	if ws == nil || len(paths) == 0 {
		return nil
	}
	index := ws.Index()
	entries := make([]Entry, 0, len(index))
	for _, obj := range index {
		entries = append(entries, Entry{Mode: obj.Mode, OID: obj.OID, Path: obj.Path, Size: obj.Size, Target: obj.Target})
	}
	tree, err := buildTree(entries)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var objs []preopen.IndexObject
	var add func(p string)
	add = func(p string) {
		if seen[p] {
			return
		}
		obj, ok := index[p]
		if !ok || obj.Mode == "160000" {
			return
		}
		seen[p] = true
		if obj.Mode != "120000" && obj.Size > maxFile {
			obj.Sparse = obj.Size
		}
		objs = append(objs, obj)
		if obj.Mode != "120000" {
			return
		}
		resolved, links, err := tree.resolve(p, 0)
		for _, link := range links {
			if link != p {
				add(link)
			}
		}
		if err != nil || resolved == nil || resolved.path == p {
			return
		}
		add(resolved.path)
	}
	for _, raw := range paths {
		cleaned, ok := cleanRef(raw)
		if !ok {
			continue
		}
		if _, ok := index[cleaned]; ok {
			add(cleaned)
			continue
		}
		resolved, links, err := tree.resolve(cleaned, 0)
		for _, link := range links {
			add(link)
		}
		if err == nil && resolved != nil {
			add(resolved.path)
		}
	}
	var missing []preopen.IndexObject
	for _, obj := range objs {
		dest := filepath.Join(ws.Tree(), filepath.FromSlash(obj.Path))
		if _, err := os.Lstat(dest); err == nil {
			continue
		}
		missing = append(missing, obj)
	}
	if len(missing) == 0 {
		return nil
	}
	return ws.Put(ctx, missing)
}

func cleanRef(raw string) (string, bool) {
	cleaned := path.Clean(strings.ReplaceAll(raw, `\`, "/"))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", false
	}
	return cleaned, true
}

func unique(oids []string) []string {
	if len(oids) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(oids))
	out := make([]string, 0, len(oids))
	for _, oid := range oids {
		if oid == "" || seen[oid] {
			continue
		}
		seen[oid] = true
		out = append(out, oid)
	}
	return out
}
