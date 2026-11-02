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

// maxMessageHead is the start of one commit message that is kept.
// maxMessageTail is the end that is kept, which is where Co-authored-by
// trailers sit. A longer message drops the middle. The head used to be
// 4MiB, which made a few thousand commits retain tens of gigabytes.
const (
	maxMessageHead = 64 << 10
	maxMessageTail = 64 << 10
)

// maxRecordBytes is the total retained size of every field of every
// commit record in one ReadCommits call. Past this budget a message
// keeps only its tail (shortened to whatever budget remains) or, when
// nothing remains, is dropped. Identity fields stay, truncated so the
// running total does not grow past the budget; a record whose SHA would
// not fit is not read.
const maxRecordBytes = 128 << 20

// maxIdentityField bounds the SHA and each name/email field. They are
// structured, normally short values. Reading and truncating each one
// independently, instead of one cap over the whole record, means a
// single oversized name (an attacker-controlled git-hash-object commit)
// can never consume the record budget before the parser has seen every
// \x1e separator: the record is still six fields wide, just with a
// truncated one, instead of failing to split at all.
const maxIdentityField = 4 << 10

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
	commits, limited, err := readLog(ctx, repo, rangeSpec, limit)
	if err != nil {
		warning, fatal := revisionWarning(err, rangeSpec)
		if fatal != nil {
			return nil, nil, fatal
		}
		return nil, []string{warning}, nil
	}
	if limited {
		warnings = append(warnings, fmt.Sprintf("commit records kept at most %d bytes; later messages kept only their trailer tail or were dropped", maxRecordBytes))
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

func readLog(ctx context.Context, repo, rangeSpec string, limit int) ([]Commit, bool, error) {
	args := []string{
		"--no-pager", "--no-optional-locks",
		"log", "-n", strconv.Itoa(limit),
		"--format=" + logFormat,
		"--end-of-options", rangeSpec,
	}
	cmd, err := gitrun.Command(ctx, repo, args...)
	if err != nil {
		return nil, false, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	var stderr capped
	stderr.max = 4096
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", gitrun.ErrNotInstalled, err)
	}
	commits, limited, readErr := parseLog(stdout)
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, false, readErr
	}
	if waitErr != nil {
		if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
			return nil, false, waitErr
		}
		return nil, false, &gitrun.ExitError{Args: []string{"log"}, Stderr: strings.TrimSpace(stderr.String()), Err: waitErr}
	}
	// git log prints newest first. Signals read oldest first, and a
	// capped range still keeps the newest commits (the ones just read).
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}
	return commits, limited, nil
}

// errRecordBudget stops parseLog before a record whose SHA would not
// fit in the byte budget. It is not a failure: the commits already read
// are returned, and ReadCommits adds a warning.
var errRecordBudget = errors.New("commit record byte budget exhausted")

func parseLog(r io.Reader) ([]Commit, bool, error) {
	in := bufio.NewReader(r)
	var budget recordBudget
	var commits []Commit
	for {
		fields, err := readRecord(in, &budget)
		if errors.Is(err, io.EOF) || errors.Is(err, errRecordBudget) {
			return commits, budget.limited, nil
		}
		if err != nil {
			return nil, false, err
		}
		if fields.identity[0] == "" {
			continue
		}
		commit, err := parseRecordFields(fields)
		if err != nil {
			return nil, false, err
		}
		commits = append(commits, commit)
	}
}

// recordBudget tracks bytes retained from git log records.
type recordBudget struct {
	used    int
	limited bool
}

func (b *recordBudget) remaining() int {
	if b.used >= maxRecordBytes {
		return 0
	}
	return maxRecordBytes - b.used
}

func (b *recordBudget) charge(n int) {
	if n > 0 {
		b.used += n
	}
}

// recordFields holds one git-log record. identity is SHA, author name,
// author email, committer name, committer email. message is already the
// single string that is retained: it is not copied again.
type recordFields struct {
	identity [5]string
	message  string
}

// readRecord reads one NUL-terminated git log record, field by field.
// The SHA and the four identity fields are each read until their
// separator, truncating at maxIdentityField and at whatever the byte
// budget still allows. The message is read until the record's NUL (see
// readMessage). Reading field by field, instead of one cap over the
// whole record, means an attacker-controlled identity field far larger
// than any legitimate name cannot prevent every separator from being
// found: the record is always six fields, one of which may be truncated,
// rather than a record the parser cannot split at all.
func readRecord(r *bufio.Reader, budget *recordBudget) (recordFields, error) {
	var fields recordFields
	if _, err := r.Peek(1); err != nil {
		if errors.Is(err, io.EOF) {
			return fields, io.EOF
		}
		return fields, err
	}
	// A SHA is 40 or 64 hex characters. Truncating it would fail the
	// record and abort the rest of the log, so stop before this record
	// when it cannot be kept whole.
	if budget.remaining() < 64 {
		budget.limited = true
		return fields, errRecordBudget
	}
	for i := 0; i < 5; i++ {
		keep := maxIdentityField
		if i > 0 {
			if rem := budget.remaining(); rem < keep {
				keep = rem
				budget.limited = true
			}
		}
		field, err := readIdentityField(r, keep)
		if err != nil {
			return fields, err
		}
		// One copy, into the string that is retained. The read buffer
		// is not kept.
		fields.identity[i] = string(field)
		budget.charge(len(fields.identity[i]))
	}
	message, err := readMessage(r, budget)
	if err != nil {
		return fields, err
	}
	fields.message = message
	return fields, nil
}

// readIdentityField reads up to the next \x1e, keeping at most maxKeep
// bytes. maxKeep may be zero, in which case the field is discarded.
// Reaching the end of input before a separator means git's output was
// cut off mid-record.
func readIdentityField(r *bufio.Reader, maxKeep int) ([]byte, error) {
	var buf bytes.Buffer
	for {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("git log record was not terminated")
		}
		if err != nil {
			return nil, err
		}
		if b == 0x1e {
			return buf.Bytes(), nil
		}
		if buf.Len() < maxKeep {
			buf.WriteByte(b)
		}
	}
}

// readMessage reads the record's message field up to its terminating
// NUL. A message keeps at most maxMessageHead bytes from the start and
// maxMessageTail bytes from the end. Once that full slice would pass
// the record budget, only the tail is kept, shortened to the bytes
// still available; when nothing is available the message is dropped.
// The returned string is the builder's own buffer, not a second copy.
func readMessage(r *bufio.Reader, budget *recordBudget) (string, error) {
	room := budget.remaining()
	if room <= 0 {
		budget.limited = true
		if err := discardMessage(r); err != nil {
			return "", err
		}
		return "", nil
	}
	headCap := maxMessageHead
	tailCap := maxMessageTail
	if room < headCap+tailCap {
		budget.limited = true
		headCap = 0
		if tailCap > room {
			tailCap = room
		}
	}
	var b strings.Builder
	var tail []byte
	if tailCap > 0 {
		tail = make([]byte, tailCap)
	}
	tailStart, tailLen := 0, 0
	headLen := 0
	pastHead := false
	for {
		c, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return "", errors.New("git log record was not terminated")
		}
		if err != nil {
			return "", err
		}
		if c == 0 {
			if err := consumeRecordNewline(r); err != nil {
				return "", err
			}
			if tailLen > 0 {
				writeRing(&b, tail, tailStart, tailLen)
			}
			message := b.String()
			budget.charge(len(message))
			return message, nil
		}
		if !pastHead {
			if headLen < headCap {
				b.WriteByte(c)
				headLen++
				if headLen == headCap {
					pastHead = true
				}
				continue
			}
			pastHead = true
		}
		if tailCap == 0 {
			continue
		}
		if tailLen < tailCap {
			tail[(tailStart+tailLen)%tailCap] = c
			tailLen++
			continue
		}
		tail[tailStart] = c
		tailStart = (tailStart + 1) % tailCap
	}
}

// discardMessage reads a message field to its terminating NUL without
// retaining it.
func discardMessage(r *bufio.Reader) error {
	for {
		c, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return errors.New("git log record was not terminated")
		}
		if err != nil {
			return err
		}
		if c == 0 {
			return consumeRecordNewline(r)
		}
	}
}

// consumeRecordNewline drops the newline git prints after the NUL that
// ends a log record. Any other byte is pushed back.
func consumeRecordNewline(r *bufio.Reader) error {
	next, err := r.ReadByte()
	if err == nil {
		if next != '\n' {
			if uerr := r.UnreadByte(); uerr != nil {
				return uerr
			}
		}
		return nil
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// writeRing appends n bytes of a ring buffer, starting at start, to b.
// It does not call Builder.Grow: Grow allocates 2*cap+n, and
// Builder.String keeps that backing array, so a Grow here would retain
// a third again as many bytes as the message. append sizes the buffer
// to the bytes actually written. Builder.String shares that buffer, so
// the tail is not copied into a second string.
func writeRing(b *strings.Builder, ring []byte, start, n int) {
	if n == 0 {
		return
	}
	if start+n <= len(ring) {
		_, _ = b.Write(ring[start : start+n])
		return
	}
	_, _ = b.Write(ring[start:])
	_, _ = b.Write(ring[:n-(len(ring)-start)])
}

func parseRecordFields(fields recordFields) (Commit, error) {
	sha := fields.identity[0]
	if !hexSHA(sha) {
		return Commit{}, fmt.Errorf("git log record has an unexpected commit %q", sha)
	}
	return Commit{
		SHA:            sha,
		AuthorName:     fields.identity[1],
		AuthorEmail:    fields.identity[2],
		CommitterName:  fields.identity[3],
		CommitterEmail: fields.identity[4],
		Message:        fields.message,
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
