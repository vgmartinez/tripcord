package prcontext

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/vgmartinez/tripcord/internal/gitrun"
)

// maxCommits is how many commits of base..head are read. A larger range
// keeps the newest commits and warns. A missing base or head (a shallow
// checkout that does not contain the range) warns and returns no commits.
const maxCommits = 5000

// maxCommitRecord bounds one git-log record. The identity fields sit at
// the start, and Co-authored-by trailers sit at the end, so a record past
// this cap keeps both ends and drops the middle.
const maxCommitRecord = 4 << 20

// maxNoteBytes bounds one refs/notes/ai note. A larger note is skipped.
const maxNoteBytes = 2 << 20

// logFormat is one record per commit, fields separated by \x1e and the
// record terminated by NUL. %B is the message, trailers included.
const logFormat = "%H%x1e%an%x1e%ae%x1e%cn%x1e%ce%x1e%B%x00"

// ReadCommits lists commits reachable from head and not from base, and
// each commit's refs/notes/ai note when it has one. Missing notes are
// not an error. A range the clone does not contain returns a warning and
// no commits. err is set only when git is missing, the repository is not
// usable, or git fails for a reason other than a missing revision.
func ReadCommits(ctx context.Context, repo, base, head string) ([]Commit, []string, error) {
	if err := ValidateRev("base", base); err != nil {
		return nil, nil, err
	}
	if err := ValidateRev("head", head); err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(repo)
	if err != nil {
		return nil, nil, &InputError{Msg: fmt.Sprintf("repository: %v", err)}
	}
	if !info.IsDir() {
		return nil, nil, &InputError{Msg: "repository is not a directory"}
	}
	rangeSpec := base + ".." + head
	countRaw, err := git(ctx, repo, "rev-list", "--count", "--end-of-options", rangeSpec)
	if err != nil {
		warning, fatal := revisionWarning(err, rangeSpec)
		if fatal != nil {
			return nil, nil, fatal
		}
		return nil, []string{warning}, nil
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(countRaw)))
	if err != nil {
		return nil, nil, fmt.Errorf("git rev-list --count: %w", err)
	}
	var warnings []string
	limit := count
	if count > maxCommits {
		limit = maxCommits
		warnings = append(warnings, fmt.Sprintf("only the newest %d commits in %s were read", maxCommits, rangeSpec))
	}
	if limit == 0 {
		return nil, warnings, nil
	}
	commits, err := readLog(ctx, repo, rangeSpec, limit)
	if err != nil {
		warning, fatal := revisionWarning(err, rangeSpec)
		if fatal != nil {
			return nil, nil, fatal
		}
		return nil, []string{warning}, nil
	}
	for i := range commits {
		note, status, err := readNote(ctx, repo, commits[i].SHA)
		if err != nil {
			return nil, nil, err
		}
		switch status {
		case noteOK:
			commits[i].Note = note
		case noteAbsent:
		case noteTooBig:
			warnings = append(warnings, fmt.Sprintf("commit %s: authorship note is larger than %d bytes and was skipped", commits[i].SHA, maxNoteBytes))
		default:
			panic(fmt.Sprintf("prcontext: unhandled note status %d", status))
		}
	}
	return commits, warnings, nil
}

type noteStatus int

const (
	noteOK noteStatus = iota
	noteAbsent
	noteTooBig
)

func git(ctx context.Context, repo string, args ...string) ([]byte, error) {
	full := make([]string, 0, len(args)+2)
	full = append(full, "--no-pager", "--no-optional-locks")
	full = append(full, args...)
	return gitrun.Run(ctx, repo, full...)
}

// revisionWarning turns a missing revision into a warning. Any other git
// failure, including a directory that is not a repository, is fatal.
func revisionWarning(err error, rangeSpec string) (warning string, fatal error) {
	classified := classifyRev(err, rangeSpec)
	var missing *historyError
	if errors.As(classified, &missing) {
		return missing.Error(), nil
	}
	return "", classified
}

// classifyRev turns a missing revision into historyError. Any other git
// failure, including a directory that is not a repository, is returned.
func classifyRev(err error, rangeSpec string) error {
	var exitErr *gitrun.ExitError
	if errors.As(err, &exitErr) {
		msg := strings.ToLower(exitErr.Stderr)
		switch {
		case strings.Contains(msg, "not a git repository"):
			return &InputError{Msg: "repository is not a git repository"}
		case strings.Contains(msg, "unknown revision"),
			strings.Contains(msg, "bad revision"),
			strings.Contains(msg, "ambiguous argument"),
			strings.Contains(msg, "invalid revision"),
			strings.Contains(msg, "needed a single revision"):
			return &historyError{rangeSpec: rangeSpec}
		}
	}
	return err
}

// historyError is a base..head the clone does not contain. ReadCommits
// converts it into a warning so a shallow checkout still reports the
// pull request's author and branch.
type historyError struct {
	rangeSpec string
}

func (e *historyError) Error() string {
	return "commit range " + e.rangeSpec + " is not in this clone; commit and note signals were skipped"
}

func readLog(ctx context.Context, repo, rangeSpec string, limit int) ([]Commit, error) {
	args := []string{
		"--no-pager", "--no-optional-locks",
		"log", "-n", strconv.Itoa(limit),
		"--format=" + logFormat,
		"--end-of-options", rangeSpec,
	}
	cmd, err := gitrun.Command(ctx, repo, args...)
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr capped
	stderr.max = 4096
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: %w", gitrun.ErrNotInstalled, err)
	}
	commits, readErr := parseLog(stdout)
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if waitErr != nil {
		if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
			return nil, waitErr
		}
		return nil, &gitrun.ExitError{Args: []string{"log"}, Stderr: strings.TrimSpace(stderr.String()), Err: waitErr}
	}
	// git log prints newest first. Signals read oldest first, and a
	// capped range still keeps the newest commits (the ones just read).
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}
	return commits, nil
}

func parseLog(r io.Reader) ([]Commit, error) {
	in := bufio.NewReader(r)
	var commits []Commit
	for {
		rec, err := readRecord(in)
		if errors.Is(err, io.EOF) {
			return commits, nil
		}
		if err != nil {
			return nil, err
		}
		if len(rec) == 0 {
			continue
		}
		commit, err := parseRecord(rec)
		if err != nil {
			return nil, err
		}
		commits = append(commits, commit)
	}
}

// readRecord reads one NUL-terminated git log record. A record longer
// than maxCommitRecord keeps its head (the identity fields) and a tail
// (the trailers) and drops the middle of the message.
func readRecord(r *bufio.Reader) ([]byte, error) {
	var head bytes.Buffer
	const tailCap = 64 << 10
	tail := make([]byte, tailCap)
	tailStart, tailLen := 0, 0
	truncated := false
	for {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			if head.Len() == 0 && tailLen == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("git log record was not terminated")
		}
		if err != nil {
			return nil, err
		}
		if b == 0 {
			// git prints a newline after the format string, past the NUL.
			if next, nerr := r.ReadByte(); nerr == nil {
				if next != '\n' {
					if uerr := r.UnreadByte(); uerr != nil {
						return nil, uerr
					}
				}
			} else if !errors.Is(nerr, io.EOF) {
				return nil, nerr
			}
			if !truncated || tailLen == 0 {
				return head.Bytes(), nil
			}
			return joinRecord(head.Bytes(), ringBytes(tail, tailStart, tailLen))
		}
		if !truncated {
			head.WriteByte(b)
			if head.Len() == maxCommitRecord {
				truncated = true
			}
			continue
		}
		tail[(tailStart+tailLen)%tailCap] = b
		if tailLen < tailCap {
			tailLen++
			continue
		}
		tailStart = (tailStart + 1) % tailCap
	}
}

func ringBytes(buf []byte, start, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = buf[(start+i)%len(buf)]
	}
	return out
}

// joinRecord replaces the commit message in head with tail. head is the
// start of the record, so its identity fields are intact.
func joinRecord(head, tail []byte) ([]byte, error) {
	parts := bytes.SplitN(head, []byte{0x1e}, 6)
	if len(parts) != 6 {
		return nil, errors.New("git log record has an unexpected shape")
	}
	rec := make([]byte, 0, len(head)+len(tail))
	for i := 0; i < 5; i++ {
		rec = append(rec, parts[i]...)
		rec = append(rec, 0x1e)
	}
	rec = append(rec, tail...)
	return rec, nil
}

func parseRecord(rec []byte) (Commit, error) {
	parts := bytes.SplitN(rec, []byte{0x1e}, 6)
	if len(parts) != 6 {
		return Commit{}, errors.New("git log record has an unexpected shape")
	}
	sha := string(parts[0])
	if !hexSHA(sha) {
		return Commit{}, fmt.Errorf("git log record has an unexpected commit %q", sha)
	}
	return Commit{
		SHA:            sha,
		AuthorName:     string(parts[1]),
		AuthorEmail:    string(parts[2]),
		CommitterName:  string(parts[3]),
		CommitterEmail: string(parts[4]),
		Message:        string(parts[5]),
	}, nil
}

func hexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func readNote(ctx context.Context, repo, sha string) (string, noteStatus, error) {
	cmd, err := gitrun.Command(ctx, repo, "--no-pager", "--no-optional-locks", "notes", "--ref=ai", "show", "--end-of-options", sha)
	if err != nil {
		return "", 0, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", 0, err
	}
	var stderr capped
	stderr.max = 4096
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", 0, fmt.Errorf("%w: %w", gitrun.ErrNotInstalled, err)
	}
	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, io.LimitReader(stdout, maxNoteBytes+1))
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
		return "", 0, waitErr
	}
	if buf.Len() > maxNoteBytes {
		return "", noteTooBig, nil
	}
	if waitErr != nil {
		msg := strings.ToLower(stderr.String())
		if strings.Contains(msg, "no note found") {
			return "", noteAbsent, nil
		}
		return "", 0, &gitrun.ExitError{Args: []string{"notes", "show"}, Stderr: strings.TrimSpace(stderr.String()), Err: waitErr}
	}
	return buf.String(), noteOK, nil
}

// capped collects at most max bytes of a git diagnostic.
type capped struct {
	buf bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len() < c.max {
		room := c.max - c.buf.Len()
		if room > len(p) {
			room = len(p)
		}
		_, _ = c.buf.Write(p[:room])
	}
	return len(p), nil
}

func (c *capped) String() string { return c.buf.String() }
