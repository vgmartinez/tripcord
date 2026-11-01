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
	"time"
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
	// MinKeyBytes is the shortest accepted key, counted after the hex
	// text is decoded: TRIPCORD_FINGERPRINT_KEY and a key file must both
	// be an even-length hex string (0-9, a-f, A-F) of at least
	// MinKeyBytes*2 characters after trimming surrounding space. The
	// decoded bytes, not the hex text, key the HMAC, so uppercase and
	// lowercase spellings of the same key are one key.
	MinKeyBytes = 16
	// minKeyHexChars is MinKeyBytes expressed as hex text length.
	minKeyHexChars = MinKeyBytes * 2
	// maxKeyFileBytes caps the key file read.
	maxKeyFileBytes = 4096
	// generatedKeyBytes is the random key length a new file gets; it is
	// stored hex-encoded, so the file holds twice as many characters.
	// 32 bytes is also what the docs recommend for a hand-written key.
	// A key file's content must be exactly this many hex characters
	// (generatedKeyBytes*2), optionally followed by one "\n": unlike
	// TRIPCORD_FINGERPRINT_KEY, nothing but Load's own createKeyFile
	// should ever produce this file's content, so an exact length is
	// safe to require and catches truncation or corruption that a
	// looser minimum-length check would silently accept.
	generatedKeyBytes = 32
	placeholder       = "fpkey.Key([redacted])"
	tempFilePattern   = ".fingerprint.key.*.tmp"
	// staleTempFileAge is how old a leftover temporary key file
	// (tempFilePattern) must be before Load removes it. createKeyFile's
	// own deferred cleanup removes its temporary file in the normal
	// case; a process killed (SIGKILL, a hard crash) between creating
	// it and that deferred cleanup running leaves it behind forever
	// otherwise. A threshold well past any realistic creation time
	// means a file this old is safe to assume orphaned, never one a
	// concurrent Load is still writing.
	staleTempFileAge = 5 * time.Minute
)

var (
	// ErrInvalid reports a key that is set but unusable: not a hex
	// string, an odd number of hex characters, shorter than
	// minKeyHexChars, or a key file larger than the size cap or not
	// exactly generatedKeyBytes*2 hex characters.
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
	// ErrCIFallback wraps ErrUnavailable (errors.Is(err, ErrUnavailable)
	// is true for it, so an existing caller that only checks for the
	// general case keeps working) for the specific, common case of CI
	// being detected with no key source at all: Load never creates a
	// key file there, by design, so the scan always runs in s1.
	// Error() is exactly ciFallbackNote, with no prefix, so a caller
	// prints it as-is.
	ErrCIFallback error = ciFallbackError{}
)

// ciFallbackNote is the whole note for a CI scan with no key source.
const ciFallbackNote = "CI detected: fingerprint key not created, using s1"

// ciFallbackError is ErrCIFallback. Error is the note alone;
// Unwrap reports ErrUnavailable.
type ciFallbackError struct{}

func (ciFallbackError) Error() string { return ciFallbackNote }

func (ciFallbackError) Unwrap() error { return ErrUnavailable }

// Key is a loaded HMAC key. The zero value and a nil *Key are "no key".
type Key struct {
	secret []byte
}

// hexAlphabet is the character class New accepts. The error text quotes
// it verbatim, so the message and the check cannot drift apart.
const hexAlphabet = "0-9, a-f, A-F"

// New returns a key over secret after trimming surrounding space, the
// same normalization the env var and the key file get, so the same text
// in either place is the same key. secret must be a hex string
// (hexAlphabet; `openssl rand -hex 32` is the documented way to generate
// one) of at least minKeyHexChars characters once trimmed, and that
// length must be even, or New returns ErrInvalid: a key that is some
// other shape is more likely to be truncated or corrupted than
// intentional, and must fail closed rather than silently produce
// different fingerprints. The decoded bytes, not the hex text, key the
// HMAC (see Sum), so "AB" and "ab" are the same key.
func New(secret string) (*Key, error) {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) < minKeyHexChars {
		return nil, fmt.Errorf("%w: shorter than %d hex characters (%d bytes)", ErrInvalid, minKeyHexChars, MinKeyBytes)
	}
	if !isHex(trimmed) {
		return nil, fmt.Errorf("%w: must be a hex string (%s)", ErrInvalid, hexAlphabet)
	}
	if len(trimmed)%2 != 0 {
		return nil, fmt.Errorf("%w: odd number of hex characters", ErrInvalid)
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: must be a hex string (%s)", ErrInvalid, hexAlphabet)
	}
	return &Key{secret: decoded}, nil
}

// isHex reports whether every character of s is a hex digit. s is never
// empty when called: callers check length first.
func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
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
		cleanStaleTempFiles(dir)
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
		return nil, SourceNone, ErrCIFallback
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

// cleanStaleTempFiles best-effort removes leftover temporary key files
// (tempFilePattern) in dir. It reads dir and matches the pattern
// against each name, never against the path: dir can contain glob
// metacharacters (a home directory literally named "h*", "h?", or
// "h["), and filepath.Glob would otherwise interpret those and delete
// a sibling directory's files, or, on an unmatched "[", match nothing
// and leave the sweep off. Only a regular file is removed. A mtime is
// stale only when it is more than staleTempFileAge old or more than
// staleTempFileAge in the future: a small future skew can come from
// another process's live write, or a filesystem clock difference.
//
// It never reports an error. Load only ever reads or creates
// fingerprint.key itself, so a failure to sweep these orphans is not
// fatal, and leaving one behind for another pass is always safe.
func cleanStaleTempFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := time.Now()
	oldCutoff := now.Add(-staleTempFileAge)
	futureCutoff := now.Add(staleTempFileAge)
	for _, entry := range entries {
		matched, err := filepath.Match(tempFilePattern, entry.Name())
		if err != nil || !matched {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		mod := info.ModTime()
		if mod.Before(oldCutoff) || mod.After(futureCutoff) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
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
	// Unlike New's general minimum-length rule for
	// TRIPCORD_FINGERPRINT_KEY, a key FILE's content must match
	// createKeyFile's output exactly: nothing legitimate ever writes
	// anything else here, so an exact length catches truncation (a
	// short write, a half-copied backup) or other corruption that a
	// looser check would silently accept as a valid, but different,
	// key, changing fingerprints without anyone noticing.
	text := strings.TrimSuffix(string(raw), "\n")
	if len(text) != generatedKeyBytes*2 || !isHex(text) {
		return nil, fmt.Errorf(
			"%w: %s must be exactly %d hex characters, optionally followed by one newline; "+
				"it may be truncated or corrupted. Delete it to let the next local scan generate "+
				"a fresh one, or replace it with the output of `openssl rand -hex %d`",
			ErrInvalid, LogicalPath, generatedKeyBytes*2, generatedKeyBytes)
	}
	k, err := New(text)
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
	// fsync the directory too, not just the file's own contents above:
	// on most filesystems the directory entry the link just added is
	// otherwise only guaranteed durable once the directory itself is
	// flushed, so a crash right after Link could, on some filesystems,
	// leave the link missing even though the file's bytes are safe on
	// disk. Best-effort: a directory that cannot be fsynced (an
	// unusual filesystem, a permission quirk) does not invalidate the
	// key file Link already published.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	k, err := New(text)
	return k, true, err
}
