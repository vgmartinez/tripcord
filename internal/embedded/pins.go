package embedded

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vgmartinez/tripcord/internal/project"
)

// KnownWorkflowPins are earlier values of WorkflowPin, oldest first.
// A repin PR appends the WorkflowPin it replaces, in the same change;
// entries are never edited or removed. A pin here is accepted as
// outdated (low), never as current. 8b33b1b and 6e1d5db never belong
// here: the tripcord-pr.yml they pin runs an action without the embed
// check. TestKnownWorkflowPinsShape checks the format;
// TestReleaseGateKnownWorkflowPins checks each entry against main and
// that the list only grows.
var KnownWorkflowPins = []string{}

// ExcludedWorkflowPins are earlier WorkflowPin values that must never be
// accepted: their tripcord-pr.yml pins an action without the embed check.
var ExcludedWorkflowPins = []string{
	"6e1d5db7a7d373b7fb4573f554af99471e1d7066",
	"8b33b1b5a69c686b611b43a475da9658fe44614d",
}

// ReusableWorkflowPath is the reusable workflow the generated
// tripcord.yml calls, relative to this repository's root.
const ReusableWorkflowPath = ".github/workflows/tripcord-pr.yml"

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// IsCommitSHA reports whether s is a full, lowercase commit SHA.
func IsCommitSHA(s string) bool { return commitPattern.MatchString(s) }

// knownPin reports whether pin is in the closed set: WorkflowPin or
// KnownWorkflowPins.
func knownPin(pin string) bool {
	return pin == WorkflowPin || slices.Contains(KnownWorkflowPins, pin)
}

// WorkflowRef is the reusable workflow a CI scan runs inside, as
// --executing-workflow names it: job.workflow_repository,
// job.workflow_file_path, and job.workflow_sha.
type WorkflowRef struct {
	Repository string
	Path       string
	SHA        string
}

// ParseWorkflowRef parses <owner>/<repo>/<path>@<sha>. Only this
// repository's tripcord-pr.yml at a full commit SHA is accepted.
func ParseWorkflowRef(s string) (*WorkflowRef, error) {
	left, sha, ok := strings.Cut(s, "@")
	if !ok || strings.Contains(sha, "@") {
		return nil, fmt.Errorf("--executing-workflow %q: want %s/%s@<40-hex sha>", s, project.Repository, ReusableWorkflowPath)
	}
	repo, path, ok := strings.Cut(left, "/.github/")
	if !ok || repo != project.Repository || ".github/"+path != ReusableWorkflowPath {
		return nil, fmt.Errorf("--executing-workflow %q: only %s/%s is accepted", s, project.Repository, ReusableWorkflowPath)
	}
	if !IsCommitSHA(sha) {
		return nil, fmt.Errorf("--executing-workflow %q: the ref must be a full 40-character lowercase commit SHA", s)
	}
	return &WorkflowRef{Repository: repo, Path: ReusableWorkflowPath, SHA: sha}, nil
}

// releaseVersionPattern is a strict X.Y.Z release. A prerelease and a
// git describe version such as 0.1.0-12-gdeadbeef are not releases:
// they do not get the newer-embed exception.
var releaseVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

// ReleaseVersion is v without a leading "v" when it is a strict X.Y.Z
// release, and "" for any other build (dev, a prerelease, a commit,
// 0.1.0-12-gdeadbeef).
func ReleaseVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if !releaseVersionPattern.MatchString(v) {
		return ""
	}
	return v
}

// PinVersion is v without a leading "v" when bootstrap.sh would accept
// it as --version, including a prerelease. It is not a release; see
// ReleaseVersion.
func PinVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if !versionPattern.MatchString(v) {
		return ""
	}
	return v
}

// CompareVersions orders two release versions by semantic-versioning
// precedence: -1 when a < b, 0 when equal, 1 when a > b. Both must be
// valid (versionPattern); build metadata is not part of the pattern.
func CompareVersions(a, b string) int {
	coreA, preA, _ := strings.Cut(a, "-")
	coreB, preB, _ := strings.Cut(b, "-")
	partsA, partsB := strings.Split(coreA, "."), strings.Split(coreB, ".")
	for i := range 3 {
		if c := compareNumeric(partsA[i], partsB[i]); c != 0 {
			return c
		}
	}
	switch {
	case preA == preB:
		return 0
	case preA == "":
		return 1
	case preB == "":
		return -1
	}
	idsA, idsB := strings.Split(preA, "."), strings.Split(preB, ".")
	for i := 0; i < len(idsA) && i < len(idsB); i++ {
		if c := comparePrerelease(idsA[i], idsB[i]); c != 0 {
			return c
		}
	}
	return compareInt(len(idsA), len(idsB))
}

func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := compareInt(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func comparePrerelease(a, b string) int {
	_, errA := strconv.ParseUint(a, 10, 64)
	_, errB := strconv.ParseUint(b, 10, 64)
	switch {
	case errA == nil && errB == nil:
		return compareNumeric(a, b)
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
