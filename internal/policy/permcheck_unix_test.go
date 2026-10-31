//go:build !windows

package policy

import (
	"os"
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
