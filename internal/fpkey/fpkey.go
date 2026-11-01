// Package fpkey resolves the optional HMAC key that keys the "sig:"
// discriminator in evidence keys, and with it every fingerprint of an
// entry that lost a secret to redaction.
//
// The key comes from TRIPCORD_FINGERPRINT_KEY (CI sets it from a
// secret) or from ~/.tripcord/fingerprint.key. Outside CI the file is
// created on first use with mode 0600; in CI it is never created. With
// no key the adapters fall back to the structural s1 discriminator,
// which is never a hash of a secret. The OS keychain replaces the file
// with the v1 store.
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
	// LogicalPath is the key file's home-relative name, used in
	// messages so no absolute home path is printed.
	LogicalPath = "~/.tripcord/fingerprint.key"
	// MinKeyBytes is the shortest accepted key after trimming space.
	MinKeyBytes = 16
	// maxKeyFileBytes caps the key file read.
	maxKeyFileBytes = 4096
	// generatedKeyBytes is the random key length a new file gets; it is
	// stored hex-encoded, so the file holds twice as many characters.
	generatedKeyBytes = 32
	placeholder       = "fpkey.Key([redacted])"
)

var (
	// ErrInvalid reports a key that is set but unusable (too short).
	ErrInvalid = errors.New("fingerprint key is invalid")
	// ErrUnavailable reports a key file that could not be read or
	// created. Callers may continue without a key (s1 mode).
	ErrUnavailable = errors.New("fingerprint key file is unavailable")
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
// created with mode 0600 in a 0700 directory. In CI (CI or
// GITHUB_ACTIONS set) the file is never created and Load returns no key.
// A failure to determine home, read, or create the file wraps
// ErrUnavailable; a key that is set but too short wraps ErrInvalid.
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
	k, err := readKeyFile(path)
	switch {
	case err == nil:
		return k, SourceFile, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, SourceNone, err
	case IsCI(getenv):
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

// IsCI reports whether CI or GITHUB_ACTIONS is set to anything other
// than empty, "0", or "false".
func IsCI(getenv func(string) string) bool {
	for _, name := range []string{"CI", "GITHUB_ACTIONS"} {
		switch strings.ToLower(strings.TrimSpace(getenv(name))) {
		case "", "0", "false":
		default:
			return true
		}
	}
	return false
}

func readKeyFile(path string) (*Key, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open %s", ErrUnavailable, LogicalPath)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnavailable, LogicalPath)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s", ErrUnavailable, LogicalPath)
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

// createKeyFile writes a new random key with O_EXCL. When another
// process won the race, it reads that file instead and reports
// created=false.
func createKeyFile(path string, random io.Reader) (*Key, bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("%w: cannot create the directory of %s", ErrUnavailable, LogicalPath)
	}
	buf := make([]byte, generatedKeyBytes)
	if _, err := io.ReadFull(random, buf); err != nil {
		return nil, false, fmt.Errorf("%w: cannot generate a key", ErrUnavailable)
	}
	text := hex.EncodeToString(buf)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		k, err := readKeyFile(path)
		return k, false, err
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: cannot create %s", ErrUnavailable, LogicalPath)
	}
	// The umask can only narrow 0600; Chmod makes the mode exact.
	werr := f.Chmod(0o600)
	if werr == nil {
		_, werr = io.WriteString(f, text+"\n")
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return nil, false, fmt.Errorf("%w: cannot write %s", ErrUnavailable, LogicalPath)
	}
	k, err := New(text)
	return k, true, err
}
