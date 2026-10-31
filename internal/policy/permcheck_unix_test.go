//go:build !windows

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeFileInfo struct {
	mode os.FileMode
	sys  any
}

func (f fakeFileInfo) Name() string       { return "dir" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode&os.ModeDir != 0 }
func (f fakeFileInfo) Sys() any           { return f.sys }

func TestManagedPolicyParentOwnership(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	otherUID := uid + 1
	if otherUID == uid {
		otherUID = 2
	}
	cases := []struct {
		name    string
		uid     uint32
		gid     uint32
		perm    os.FileMode
		sys     any
		wantErr string
	}{
		{name: "owned by us", uid: uid, gid: gid, perm: 0o770},
		{name: "root", uid: 0, gid: gid ^ 1, perm: 0o755},
		{name: "world writable", uid: uid, gid: gid, perm: 0o777, wantErr: "world-writable"},
		{name: "other owner", uid: otherUID, gid: gid, perm: 0o755, wantErr: "owned by uid"},
		{name: "group writable not ours", uid: uid, gid: gid + 1, perm: 0o770, wantErr: "group-writable"},
		{name: "root group writable", uid: 0, gid: gid, perm: 0o775, wantErr: "group-writable"},
		{name: "unknown owner", perm: 0o755, sys: "not a stat", wantErr: "owner is unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "root group writable" && os.Getuid() == 0 {
				t.Skip("the current user is root, so this directory is ours")
			}
			sys := tc.sys
			if sys == nil {
				sys = &syscall.Stat_t{Uid: tc.uid, Gid: tc.gid}
			}
			err := checkManagedPolicyParent("policy.yaml", fakeFileInfo{mode: os.ModeDir | tc.perm, sys: sys})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestManagedPolicyAncestorOwnership(t *testing.T) {
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	otherUID := uid + 1
	if otherUID == uid {
		otherUID = 2
	}
	cases := []struct {
		name    string
		uid     uint32
		gid     uint32
		perm    os.FileMode
		sticky  bool
		sys     any
		wantErr string
	}{
		{name: "owned by us", uid: uid, gid: gid, perm: 0o770},
		{name: "root", uid: 0, gid: gid ^ 1, perm: 0o755},
		{name: "world writable without sticky", uid: 0, gid: gid ^ 1, perm: 0o777, wantErr: "world-writable"},
		{name: "world writable with sticky is safe (e.g. /tmp)", uid: 0, gid: gid ^ 1, perm: 0o777, sticky: true},
		{name: "group writable not ours without sticky", uid: uid, gid: gid + 1, perm: 0o770, wantErr: "group-writable"},
		{name: "group writable not ours with sticky is safe", uid: uid, gid: gid + 1, perm: 0o770, sticky: true},
		{name: "other owner", uid: otherUID, gid: gid, perm: 0o755, wantErr: "owned by uid"},
		{name: "unknown owner", perm: 0o755, sys: "not a stat", wantErr: "owner is unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := tc.sys
			if sys == nil {
				sys = &syscall.Stat_t{Uid: tc.uid, Gid: tc.gid}
			}
			mode := os.ModeDir | tc.perm
			if tc.sticky {
				mode |= os.ModeSticky
			}
			err := checkManagedPolicyAncestor("policy.yaml", fakeFileInfo{mode: mode, sys: sys})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestCheckManagedPolicyParentPathWalksAncestors checks the walk on real
// directories: a world-writable grandparent is rejected even though the
// immediate parent is safe, and setting the sticky bit on that same
// grandparent (as /tmp does) makes it safe again.
func TestCheckManagedPolicyParentPathWalksAncestors(t *testing.T) {
	root := t.TempDir()
	grandparent := filepath.Join(root, "grandparent")
	parent := filepath.Join(grandparent, "parent")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(parent, "policy.yaml")

	if err := checkManagedPolicyParentPath(policyPath); err != nil {
		t.Fatalf("safe ancestors: %v", err)
	}

	if err := os.Chmod(grandparent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkManagedPolicyParentPath(policyPath); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable grandparent without sticky: err = %v", err)
	}

	if err := os.Chmod(grandparent, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := checkManagedPolicyParentPath(policyPath); err != nil {
		t.Fatalf("sticky world-writable grandparent should be safe: %v", err)
	}
}

// TestCheckManagedPolicyParentPathFollowsAncestorSymlinks checks that the
// walk follows a symlinked ancestor to its real target before continuing
// upward. The policy file's parent is reached only through a symlink
// ("linkbase/alias" points at "insecure/real"); the real ancestor two
// levels up ("insecure") is world-writable without a sticky bit, but it
// is not an ancestor of the symlink's own location ("linkbase") at all.
// A walk that kept using the literal, pre-symlink path to compute each
// next ancestor (plain filepath.Dir, as the walk did before resolving
// path's parent with filepath.EvalSymlinks) would drift onto
// "linkbase"'s own, unrelated and safe ancestors and never see
// "insecure" at all, silently accepting a managed policy an attacker who
// controls "insecure" could substitute.
func TestCheckManagedPolicyParentPathFollowsAncestorSymlinks(t *testing.T) {
	base := t.TempDir()
	insecureAncestor := filepath.Join(base, "insecure")
	realDir := filepath.Join(insecureAncestor, "real")
	subDir := filepath.Join(realDir, "sub")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(insecureAncestor, 0o777); err != nil {
		t.Fatal(err)
	}

	linkBase := filepath.Join(base, "linkbase")
	if err := os.Mkdir(linkBase, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkBase, "alias")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(link, "sub", "policy.yaml")
	if err := checkManagedPolicyParentPath(policyPath); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("checkManagedPolicyParentPath(%q) = %v, want a world-writable error for the symlink's real ancestor", policyPath, err)
	}
}

// TestCheckManagedPolicyParentPathRedactsHomeDirectory checks that an
// error from checkManagedPolicyParentPath never embeds the running
// user's home directory, the same way every other diagnostic in this
// codebase redacts it; see redactPath.
func TestCheckManagedPolicyParentPathRedactsHomeDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	parent := filepath.Join(home, "insecure-parent")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(parent, "policy.yaml")
	err := checkManagedPolicyParentPath(policyPath)
	if err == nil {
		t.Fatal("want an error for a world-writable parent")
	}
	if strings.Contains(err.Error(), home) {
		t.Fatalf("checkManagedPolicyParentPath(%q) = %v, leaks the home directory", policyPath, err)
	}
	if !strings.Contains(err.Error(), "~") {
		t.Fatalf("checkManagedPolicyParentPath(%q) = %v, want the home directory rewritten to ~", policyPath, err)
	}
}
