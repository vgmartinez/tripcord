// Package fpkey resolves the optional HMAC key that keys the "sig:"
// discriminator in evidence keys, and with it every fingerprint of an
// entry that lost a secret to redaction.
//
// The key comes from TRIPCORD_FINGERPRINT_KEY (CI sets it from a
// secret) or from ~/.tripcord/fingerprint.key. Outside CI the file is
// created on first use with mode 0600, written atomically so a
// concurrent run never observes a partial file. In CI it is never
// created. With no key source at all the adapters fall back to the
// structural s1 discriminator, which is never a hash of a secret.
//
// Key material that exists but is broken — unreadable, corrupt, too
// short, a symlink, owned by someone else, or wider than its expected
// permissions — fails the scan closed instead of silently falling back
// to s1: a fingerprint mode must never change without the caller
// noticing. The OS keychain replaces the file with the v1 store.
//
// A Key never prints its bytes: every fmt verb, String, GoString, and
// MarshalJSON render a fixed placeholder, and no error names its value.
package fpkey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// EnvVar names the environment variable that holds the key.
	EnvVar = "TRIPCORD_FINGERPRINT_KEY"
	// LogicalDir is the key file's home-relative directory, used in
	// messages so no absolute home path is printed.
	LogicalDir = "~/.tripcord"
	// LogicalPath is the key file's home-relative name, used in
	// messages so no absolute home path is printed.
	LogicalPath = LogicalDir + "/fingerprint.key"
	// MinKeyBytes is the shortest accepted key after trimming space.
	MinKeyBytes = 16
	// maxKeyFileBytes caps the key file read.
	maxKeyFileBytes = 4096
	// generatedKeyBytes is the random key length a new file gets; it is
	// stored hex-encoded, so the file holds twice as many characters.
	// 32 bytes is also what the docs recommend for a hand-written key.
	generatedKeyBytes = 32
	placeholder       = "fpkey.Key([redacted])"
	tempFilePattern   = ".fingerprint.key.*.tmp"
)

var (
	// ErrInvalid reports a key that is set but unusable (too short, or
	// a key file larger than the size cap).
	ErrInvalid = errors.New("fingerprint key is invalid")
	// ErrUnavailable reports that no key source exists at all: the
	// home directory could not be determined, or a new key file could
	// not be generated or created for an environmental reason (a
	// read-only home, for example). Neither case touches existing key
	// material, so callers may continue without a key (s1 mode).
	ErrUnavailable = errors.New("fingerprint key file is unavailable")
	// ErrKeyUnusable reports that key material already EXISTS but is
	// broken: unreadable, not a regular file, a symlink, owned by
	// someone else, wider than its expected permissions, or
	// ~/.tripcord exists but is not a directory. Callers must fail
	// closed (never fall back to s1) so a fingerprint mode never
	// changes silently.
	ErrKeyUnusable = errors.New("fingerprint key material is unusable")
)

// Key is a loaded HMAC key. The zero value and a nil *Key are "no key".
type Key struct {
	secret []byte
}

// New returns a key over secret after trimming surrounding space, the
// same normalization the env var and the key file get, so the same text
// in either place is the same key.
func New(secret string) (*Key, error) {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) < MinKeyBytes {
		return nil, fmt.Errorf("%w: shorter than %d bytes", ErrInvalid, MinKeyBytes)
	}
	return &Key{secret: []byte(trimmed)}, nil
}

// Present reports whether k holds a key.
func (k *Key) Present() bool { return k != nil && len(k.secret) > 0 }

// Sum returns the first hexLen lowercase hex characters of
// HMAC-SHA256(k, domain || 0x00 || JSON(parts)). JSON encoding keeps
// part boundaries unambiguous. It panics on a missing key: callers pick
// the keyed mode only when Present is true.
func (k *Key) Sum(domain string, parts []string, hexLen int) string {
	if !k.Present() {
		panic("fpkey: Sum without a key")
	}
	msg, _ := json.Marshal(parts)
	mac := hmac.New(sha256.New, k.secret)
	_, _ = io.WriteString(mac, domain)
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))[:hexLen]
}

// String implements fmt.Stringer without revealing the key.
func (Key) String() string { return placeholder }

// GoString implements fmt.GoStringer without revealing the key.
func (Key) GoString() string { return placeholder }

// Format renders the placeholder for every verb, so %x or %+v cannot
// print the key either. The printing methods have value receivers so a
// dereferenced Key, or one nested in a struct, is covered too.
func (Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, placeholder) }

// MarshalJSON renders the placeholder, never the key.
func (Key) MarshalJSON() ([]byte, error) { return json.Marshal(placeholder) }

// Source says where Load found the key.
type Source int

const (
	// SourceNone means no key: s1 mode.
	SourceNone Source = iota
	// SourceEnv is TRIPCORD_FINGERPRINT_KEY.
	SourceEnv
	// SourceFile is an existing ~/.tripcord/fingerprint.key.
	SourceFile
	// SourceCreated is a key file Load just created.
	SourceCreated
)

// Options controls Load. Zero values use the process environment and
// os.UserHomeDir.
type Options struct {
	Getenv func(string) string
	Home   string
	// Rand overrides crypto/rand for a new key file.
	Rand io.Reader
}

// Load resolves the key: TRIPCORD_FINGERPRINT_KEY when set, else an
// existing ~/.tripcord/fingerprint.key, else, outside CI, a new key file
// created with mode 0600 in a 0700 directory. In CI (CI, GITHUB_ACTIONS,
// or another recognized CI environment variable set) the file is never
// created and Load returns no key.
//
// A key that is set but too short, or a key file larger than the size
// cap, wraps ErrInvalid. A failure to determine the home directory, or
// to generate or create a brand-new key file, wraps ErrUnavailable and
// is safe to treat as s1 mode. Anything wrong with key material that
// already exists on disk — unreadable, corrupt, a symlink, the wrong
// owner, too-wide permissions, or ~/.tripcord existing as a
// non-directory — wraps ErrKeyUnusable and must fail the caller closed:
// it is never safe to silently fall back to s1 once a key was supposed
// to be in play.
func Load(opts Options) (*Key, Source, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if v := getenv(EnvVar); strings.TrimSpace(v) != "" {
		k, err := New(v)
		if err != nil {
			return nil, SourceNone, fmt.Errorf("%s: %w", EnvVar, err)
		}
		return k, SourceEnv, nil
	}
	home := opts.Home
	if home == "" {
		var err error
		if home, err = os.UserHomeDir(); err != nil || home == "" {
			return nil, SourceNone, fmt.Errorf("%w: cannot determine the home directory", ErrUnavailable)
		}
	}
	path := Path(home)
	dir := filepath.Dir(path)
	dirErr := checkKeyDir(dir)
	switch {
	case dirErr == nil:
		k, err := readKeyFile(path)
		switch {
		case err == nil:
			return k, SourceFile, nil
		case !errors.Is(err, fs.ErrNotExist):
			return nil, SourceNone, err
		}
		// The directory exists but the key file does not: fall
		// through to maybe create one below.
	case !errors.Is(dirErr, fs.ErrNotExist):
		// The directory exists but is unsafe (not a directory, a
		// symlink, the wrong owner, or too permissive). That is
		// broken existing material, not a missing key source: fail
		// closed rather than silently using s1.
		return nil, SourceNone, dirErr
	}
	if IsCI(getenv) {
		return nil, SourceNone, nil
	}
	random := opts.Rand
	if random == nil {
		random = rand.Reader
	}
	k, created, err := createKeyFile(path, random)
	if err != nil {
		return nil, SourceNone, err
	}
	if !created {
		return k, SourceFile, nil
	}
	return k, SourceCreated, nil
}

// Path is the key file under home.
func Path(home string) string {
	return filepath.Join(home, ".tripcord", "fingerprint.key")
}

// IsCI reports whether a recognized CI environment variable is set to
// anything other than empty, "0", or "false". Beyond the generic CI and
// GITHUB_ACTIONS, this recognizes the indicators several other CI
// systems set unconditionally: Jenkins (JENKINS_URL), Azure Pipelines
// (TF_BUILD), AWS CodeBuild (CODEBUILD_BUILD_ID), TeamCity
// (TEAMCITY_VERSION), Buildkite (BUILDKITE), GitLab CI (GITLAB_CI), and
// CircleCI (CIRCLECI).
func IsCI(getenv func(string) string) bool {
	for _, name := range []string{
		"CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD", "CODEBUILD_BUILD_ID",
		"TEAMCITY_VERSION", "BUILDKITE", "GITLAB_CI", "CIRCLECI",
	} {
		switch strings.ToLower(strings.TrimSpace(getenv(name))) {
		case "", "0", "false":
		default:
			return true
		}
	}
	return false
}

// checkKeyDir reports whether dir is safe to hold the key file: it must
// not exist as anything but a real directory, must not be a symlink,
// and (where the platform supports the check) must be owned by the
// current user and not group- or world-writable. A dir that does not
// exist at all is reported as fs.ErrNotExist, which Load treats as "no
// key source yet" rather than broken material.
func checkKeyDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err != nil {
		return fmt.Errorf("%w: cannot stat the directory of %s", ErrKeyUnusable, LogicalPath)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s must not be a symlink", ErrKeyUnusable, LogicalDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s exists but is not a directory", ErrKeyUnusable, LogicalDir)
	}
	return checkDirSecurity(info, dir)
}

// readKeyFile reads and validates an existing key file. It never follows
// a symlink at path: a key file must be a plain regular file that the
// current user owns and that nobody else can read, so Load can trust
// that only this process's earlier run, not an attacker, placed it
// there.
func readKeyFile(path string) (*Key, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: cannot stat %s", ErrKeyUnusable, LogicalPath)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		if _, targetErr := os.Stat(path); errors.Is(targetErr, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s is a broken symlink", ErrKeyUnusable, LogicalPath)
		}
		return nil, fmt.Errorf("%w: %s must not be a symlink", ErrKeyUnusable, LogicalPath)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrKeyUnusable, LogicalPath)
	}
	if err := checkFileSecurity(info, path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open %s", ErrKeyUnusable, LogicalPath)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s", ErrKeyUnusable, LogicalPath)
	}
	if len(raw) > maxKeyFileBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrInvalid, LogicalPath, maxKeyFileBytes)
	}
	k, err := New(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", LogicalPath, err)
	}
	return k, nil
}

// createKeyFile writes a new random key. The content is written to a
// temporary file in the same directory, flushed, and then published
// with os.Link, which atomically fails with fs.ErrExist if the final
// path already exists rather than truncating or racing a concurrent
// writer. A process that loses the race reads the file the winner just
// finished instead, so every concurrent Load agrees on one key and none
// ever observes a partially written file.
func createKeyFile(path string, random io.Reader) (*Key, bool, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("%w: cannot create the directory of %s", ErrUnavailable, LogicalDir)
	}
	buf := make([]byte, generatedKeyBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return nil, false, fmt.Errorf("%w: cannot generate a key", ErrUnavailable)
	}
	text := hex.EncodeToString(buf)
	tmp, err := os.CreateTemp(dir, tempFilePattern)
	if err != nil {
		return nil, false, fmt.Errorf("%w: cannot create a temporary file for %s", ErrUnavailable, LogicalPath)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	werr := tmp.Chmod(0o600)
	if werr == nil {
		_, werr = io.WriteString(tmp, text+"\n")
	}
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, false, fmt.Errorf("%w: cannot write %s", ErrUnavailable, LogicalPath)
	}
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			k, err := readKeyFile(path)
			return k, false, err
		}
		return nil, false, fmt.Errorf("%w: cannot create %s", ErrUnavailable, LogicalPath)
	}
	k, err := New(text)
	return k, true, err
}
