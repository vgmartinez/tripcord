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
	commits, limited, err := readCommitObjects(ctx, repo, rangeSpec, limit)
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
	var oversizedNotes, malformedNotes, limitedToolsNotes int
	for i := range commits {
		tools, limited, status, err := readNote(ctx, repo, commits[i].SHA)
		if err != nil {
			return nil, nil, err
		}
		switch status {
		case noteOK:
			commits[i].NoteTools = tools
			if limited {
				limitedToolsNotes++
			}
		case noteAbsent:
		case noteTooBig:
			oversizedNotes++
		case noteNotAuthorship:
			malformedNotes++
		default:
			panic(fmt.Sprintf("prcontext: unhandled note status %d", status))
		}
	}
	if oversizedNotes > 0 {
		warnings = append(warnings, fmt.Sprintf("%d authorship notes were larger than %d bytes and were skipped", oversizedNotes, maxNoteBytes))
	}
	if malformedNotes > 0 {
		warnings = append(warnings, fmt.Sprintf("%d authorship notes were not git-ai authorship logs and were skipped", malformedNotes))
	}
	if limitedToolsNotes > 0 {
		warnings = append(warnings, fmt.Sprintf("%d authorship notes kept at most %d distinct tools each; later tools were skipped", limitedToolsNotes, maxToolsPerNote))
	}
	return commits, warnings, nil
}

type noteStatus int

const (
	noteOK noteStatus = iota
	noteAbsent
	noteTooBig
	noteNotAuthorship
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
			strings.Contains(msg, "needed a single revision"),
			strings.Contains(msg, "invalid symmetric difference"),
			strings.Contains(msg, "no merge base"):
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

// readCommitObjects gets only the bounded set of object IDs with rev-list
// and streams each raw commit through cat-file. git log formats every commit
// in the child process before it writes stdout, so a compact pack can make
// the child expand gigabytes of commit messages at once.
func readCommitObjects(ctx context.Context, repo, rangeSpec string, limit int) ([]Commit, bool, error) {
	raw, err := git(ctx, repo, "rev-list", "-n", strconv.Itoa(limit), "--end-of-options", rangeSpec)
	if err != nil {
		return nil, false, err
	}
	shas := strings.Fields(string(raw))
	var budget recordBudget
	var commits []Commit
	catCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cat, err := gitrun.Command(catCtx, repo, "--no-pager", "--no-optional-locks", "cat-file", "--batch")
	if err != nil {
		return nil, false, err
	}
	stdin, err := cat.StdinPipe()
	if err != nil {
		return nil, false, err
	}
	stdout, err := cat.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	var stderr capped
	stderr.max = 4096
	cat.Stderr = &stderr
	if err := cat.Start(); err != nil {
		return nil, false, fmt.Errorf("%w: %w", gitrun.ErrNotInstalled, err)
	}
	in := bufio.NewReader(stdout)
	var readErr error
	for _, sha := range shas {
		if budget.remaining() < 64 {
			budget.limited = true
			break
		}
		commit, err := readBatchCommit(stdin, in, sha, &budget)
		if err != nil {
			readErr = err
			break
		}
		commits = append(commits, commit)
	}
	stopped := readErr != nil || budget.limited
	if stopped {
		// cat-file writes a whole object before it reads another request.
		// Cancelling makes Wait bounded when parsing stops early.
		cancel()
	}
	_ = stdin.Close()
	waitErr := cat.Wait()
	if readErr != nil {
		return nil, false, readErr
	}
	if budget.limited {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		return commits, true, nil
	}
	if waitErr != nil {
		if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
			return nil, false, waitErr
		}
		return nil, false, &gitrun.ExitError{Args: []string{"cat-file", "--batch"}, Stderr: strings.TrimSpace(stderr.String()), Err: waitErr}
	}
	// rev-list emits newest first. Signals consume oldest first.
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}
	return commits, budget.limited, nil
}

// readBatchCommit requests sha and parses its raw commit object. The
// cat-file response is "<sha> commit <size>\n", exactly size raw bytes,
// then a framing newline.
func readBatchCommit(req io.Writer, resp *bufio.Reader, sha string, budget *recordBudget) (Commit, error) {
	if !hexSHA(sha) {
		return Commit{}, fmt.Errorf("rev-list returned an unexpected commit %q", sha)
	}
	if _, err := io.WriteString(req, sha+"\n"); err != nil {
		return Commit{}, err
	}
	header, err := resp.ReadString('\n')
	if err != nil {
		return Commit{}, err
	}
	fields := strings.Fields(header)
	if len(fields) != 3 || fields[0] != sha || fields[1] != "commit" {
		return Commit{}, fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(header))
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return Commit{}, fmt.Errorf("unexpected cat-file header %q", strings.TrimSpace(header))
	}
	body := &io.LimitedReader{R: resp, N: size}
	in := bufio.NewReader(body)
	commit, parseErr := parseRawCommit(in, sha, budget)
	_, drainErr := io.Copy(io.Discard, in)
	framing, framingErr := resp.ReadByte()
	switch {
	case parseErr != nil:
		return Commit{}, parseErr
	case drainErr != nil:
		return Commit{}, drainErr
	case framingErr != nil:
		return Commit{}, framingErr
	case framing != '\n':
		return Commit{}, errors.New("unexpected cat-file framing")
	}
	return commit, nil
}

// parseRawCommit reads raw commit headers and then its message. Identity
// lines are scanned byte by byte, so an attacker-controlled name cannot
// allocate an unbounded line before the 4KiB cap applies.
func parseRawCommit(r *bufio.Reader, sha string, budget *recordBudget) (Commit, error) {
	if budget.remaining() < 64 {
		budget.limited = true
		return Commit{}, errRecordBudget
	}
	commit := Commit{SHA: sha}
	budget.charge(len(sha))
	for {
		peek, err := r.Peek(1)
		if errors.Is(err, io.EOF) {
			return Commit{}, errors.New("raw commit headers were not terminated")
		}
		if err != nil {
			return Commit{}, err
		}
		if peek[0] == '\n' {
			_, _ = r.ReadByte()
			break
		}
		switch {
		case hasPrefix(r, "author "):
			commit.AuthorName, commit.AuthorEmail, err = readRawIdentity(r, "author ", budget)
		case hasPrefix(r, "committer "):
			commit.CommitterName, commit.CommitterEmail, err = readRawIdentity(r, "committer ", budget)
		default:
			err = discardRawLine(r)
		}
		if err != nil {
			return Commit{}, err
		}
	}
	message, err := readRawMessage(r, budget)
	if err != nil {
		return Commit{}, err
	}
	commit.Message = message
	return commit, nil
}

func hasPrefix(r *bufio.Reader, prefix string) bool {
	b, err := r.Peek(len(prefix))
	return err == nil && string(b) == prefix
}

// readRawIdentity consumes an author or committer header. It retains only
// capped name/email fields and discards timestamps and oversized data.
func readRawIdentity(r *bufio.Reader, prefix string, budget *recordBudget) (string, string, error) {
	for range prefix {
		if _, err := r.ReadByte(); err != nil {
			return "", "", err
		}
	}
	nameCap := min(maxIdentityField, budget.remaining())
	if nameCap < maxIdentityField {
		budget.limited = true
	}
	var name, email bytes.Buffer
	for {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return "", "", errors.New("raw commit identity was not terminated")
		}
		if err != nil {
			return "", "", err
		}
		if b == '\n' {
			budget.charge(name.Len())
			return name.String(), "", nil
		}
		if b != '<' {
			if name.Len() < nameCap {
				name.WriteByte(b)
			}
			continue
		}
		if name.Len() > 0 && name.Bytes()[name.Len()-1] == ' ' {
			name.Truncate(name.Len() - 1)
		}
		budget.charge(name.Len())
		emailCap := min(maxIdentityField, budget.remaining())
		if emailCap < maxIdentityField {
			budget.limited = true
		}
		for {
			b, err = r.ReadByte()
			if errors.Is(err, io.EOF) {
				return "", "", errors.New("raw commit identity was not terminated")
			}
			if err != nil {
				return "", "", err
			}
			if b == '>' || b == '\n' {
				break
			}
			if email.Len() < emailCap {
				email.WriteByte(b)
			}
		}
		budget.charge(email.Len())
		if b == '\n' {
			return name.String(), email.String(), nil
		}
		if err := discardRawLine(r); err != nil {
			return "", "", err
		}
		return name.String(), email.String(), nil
	}
}

func discardRawLine(r *bufio.Reader) error {
	for {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			return errors.New("raw commit header was not terminated")
		}
		if err != nil {
			return err
		}
		if b == '\n' {
			return nil
		}
	}
}

// readRawMessage reads the remainder of a raw commit object. Unlike the old
// porcelain log parser it ends at EOF of this object's bounded reader, not
// at a NUL record separator.
func readRawMessage(r *bufio.Reader, budget *recordBudget) (string, error) {
	room := budget.remaining()
	if room <= 0 {
		budget.limited = true
		_, err := io.Copy(io.Discard, r)
		return "", err
	}
	headCap := maxMessageHead
	tailCap := maxMessageTail
	if room < headCap+tailCap {
		budget.limited = true
		headCap = 0
		tailCap = min(tailCap, room)
	}
	var b strings.Builder
	tail := make([]byte, tailCap)
	tailStart, tailLen := 0, 0
	headLen := 0
	for {
		c, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			if tailLen > 0 {
				writeRing(&b, tail, tailStart, tailLen)
			}
			message := b.String()
			budget.charge(len(message))
			return message, nil
		}
		if err != nil {
			return "", err
		}
		if headLen < headCap {
			b.WriteByte(c)
			headLen++
			continue
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

// errRecordBudget stops reading before a record whose SHA would not fit in
// the byte budget. It is not a failure: the commits already read are
// returned, and ReadCommits adds a warning.
var errRecordBudget = errors.New("commit record byte budget exhausted")

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
//
//nolint:unused // retained only for focused legacy parser tests.
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
//
//nolint:unused // retained only for focused legacy parser tests.
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
//
//nolint:unused // retained only for focused legacy parser tests.
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

func readNote(ctx context.Context, repo, sha string) ([]string, bool, noteStatus, error) {
	cmd, err := gitrun.Command(ctx, repo, "--no-pager", "--no-optional-locks", "notes", "--ref=ai", "show", "--end-of-options", sha)
	if err != nil {
		return nil, false, 0, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, 0, err
	}
	var stderr capped
	stderr.max = 4096
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, false, 0, fmt.Errorf("%w: %w", gitrun.ErrNotInstalled, err)
	}
	limited := &io.LimitedReader{R: stdout, N: maxNoteBytes + 1}
	tools, toolLimited, parseErr := toolsFromNoteReader(limited)
	_, copyErr := io.Copy(io.Discard, limited)
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if copyErr != nil {
		return nil, false, 0, copyErr
	}
	if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
		return nil, false, 0, waitErr
	}
	if limited.N == 0 {
		return nil, false, noteTooBig, nil
	}
	if waitErr != nil {
		msg := strings.ToLower(stderr.String())
		if strings.Contains(msg, "no note found") {
			return nil, false, noteAbsent, nil
		}
		return nil, false, 0, &gitrun.ExitError{Args: []string{"notes", "show"}, Stderr: strings.TrimSpace(stderr.String()), Err: waitErr}
	}
	if parseErr != nil {
		return nil, false, noteNotAuthorship, nil
	}
	return tools, toolLimited, noteOK, nil
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
