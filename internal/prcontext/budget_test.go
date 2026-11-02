package prcontext

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const budgetTrailer = "\nCo-authored-by: Claude <noreply@anthropic.com>\n"

func TestReadMessageKeepsHeadTailAndTrailer(t *testing.T) {
	const mid = "MID-MARKER-NOT-A-TRAILER"
	message := strings.Repeat("x", maxMessageHead) + mid + strings.Repeat("y", maxMessageTail) + budgetTrailer
	var budget recordBudget
	got, err := readMessage(bufio.NewReader(strings.NewReader(message+"\x00\n")), &budget)
	if err != nil {
		t.Fatal(err)
	}
	if budget.limited {
		t.Fatal("one message under the record budget should not set limited")
	}
	if len(got) != maxMessageHead+maxMessageTail {
		t.Fatalf("len = %d, want %d", len(got), maxMessageHead+maxMessageTail)
	}
	if !strings.HasPrefix(got, strings.Repeat("x", 64)) || strings.Contains(got, mid) {
		t.Fatalf("message = %q…, want the head kept and the middle dropped", got[:64])
	}
	if authors := coAuthors(got); len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com") {
		t.Fatalf("coAuthors = %v, want the trailer in the tail", authors)
	}
	if budget.used != len(got) {
		t.Fatalf("charged %d, message len %d", budget.used, len(got))
	}
}

func TestReadMessageTailOnlyNearBudget(t *testing.T) {
	const room = 4096
	message := "HEAD-ONLY" + strings.Repeat("x", maxMessageHead+maxMessageTail) + budgetTrailer
	budget := recordBudget{used: maxRecordBytes - room}
	got, err := readMessage(bufio.NewReader(strings.NewReader(message+"\x00\n")), &budget)
	if err != nil {
		t.Fatal(err)
	}
	if !budget.limited {
		t.Fatal("a message past the remaining budget should set limited")
	}
	if len(got) != room {
		t.Fatalf("len = %d, want the %d bytes still in the budget", len(got), room)
	}
	if strings.Contains(got, "HEAD-ONLY") {
		t.Fatal("tail-only message kept the head")
	}
	if authors := coAuthors(got); len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com") {
		t.Fatalf("coAuthors = %v, want the trailer kept in the shortened tail", authors)
	}
	if budget.used != maxRecordBytes {
		t.Fatalf("used = %d, want the budget filled exactly", budget.used)
	}
}

func TestReadMessageDroppedWhenBudgetSpent(t *testing.T) {
	budget := recordBudget{used: maxRecordBytes}
	got, err := readMessage(bufio.NewReader(strings.NewReader("hello\x00\n")), &budget)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" || !budget.limited || budget.used != maxRecordBytes {
		t.Fatalf("got %q limited %v used %d", got, budget.limited, budget.used)
	}
}

func TestReadRecordStopsBeforeTruncatingSHA(t *testing.T) {
	budget := recordBudget{used: maxRecordBytes - 63}
	_, err := parseRawCommit(
		bufio.NewReader(bytes.NewReader(rawCommitObject("hello\n"))),
		"0123456789abcdef0123456789abcdef01234567",
		&budget,
	)
	if !errors.Is(err, errRecordBudget) {
		t.Fatalf("err = %v, want errRecordBudget", err)
	}
	if !budget.limited || budget.used != maxRecordBytes-63 {
		t.Fatalf("limited %v used %d, want the record unread", budget.limited, budget.used)
	}
}

// TestRecordByteBudget is the regression test for a log that caps each
// message but not the total. Enough records are offered that keeping
// every message whole would retain more than maxRecordBytes. The parser
// must stop at that budget, keep trailers in whatever tail still fits,
// and not retain a second copy of the messages it kept.
func TestRecordByteBudget(t *testing.T) {
	const extra = 64 << 10
	message := strings.Repeat("x", maxMessageHead) + strings.Repeat("m", extra) + strings.Repeat("y", maxMessageTail) + budgetTrailer
	rec := rawCommitObject(message)
	n := maxRecordBytes/(maxMessageHead+maxMessageTail) + 8
	if n*len(message) <= maxRecordBytes {
		t.Fatalf("fixture retains %d bytes if uncapped, which does not exceed %d", n*len(message), maxRecordBytes)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var budget recordBudget
	var commits []Commit
	for range n {
		commit, err := parseRawCommit(bufio.NewReader(bytes.NewReader(rec)), "0123456789abcdef0123456789abcdef01234567", &budget)
		if errors.Is(err, errRecordBudget) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		commits = append(commits, commit)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if !budget.limited {
		t.Fatal("limited = false, want the record budget exhausted")
	}
	if len(commits) == 0 || len(commits) >= n {
		t.Fatalf("commits = %d, want a non-empty prefix of %d (stopped at the budget)", len(commits), n)
	}
	if len(commits)*len(message) <= maxRecordBytes {
		t.Fatalf("%d commits of %d-byte messages fit in the budget, so this does not prove the cap", len(commits), len(message))
	}

	var total int
	var tailOnly bool
	for i, c := range commits {
		kept := len(c.SHA) + len(c.AuthorName) + len(c.AuthorEmail) + len(c.CommitterName) + len(c.CommitterEmail) + len(c.Message)
		total += kept
		if len(c.Message) > maxMessageHead+maxMessageTail {
			t.Fatalf("commit %d message len %d exceeds head+tail", i, len(c.Message))
		}
		if len(c.Message) > 0 && len(c.Message) <= maxMessageTail && !strings.HasPrefix(c.Message, strings.Repeat("x", 64)) {
			authors := coAuthors(c.Message)
			if len(c.Message) >= len(budgetTrailer) && (len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com")) {
				t.Fatalf("tail-only message lost its trailer: len %d coAuthors %v", len(c.Message), authors)
			}
			tailOnly = true
		}
	}
	if total > maxRecordBytes {
		t.Fatalf("retained %d bytes, budget %d", total, maxRecordBytes)
	}
	if !tailOnly {
		t.Fatal("no message was reduced to its tail")
	}
	first := commits[0].Message
	if len(first) != maxMessageHead+maxMessageTail || !strings.HasPrefix(first, strings.Repeat("x", 64)) || strings.Contains(first, strings.Repeat("m", 32)) {
		t.Fatalf("first message len %d, want head+tail with the middle dropped", len(first))
	}
	if authors := coAuthors(first); len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com") {
		t.Fatalf("first coAuthors = %v", authors)
	}

	// A second copy of every retained message would push the heap past
	// the budget by more than this slack. Builder.String shares its
	// buffer, so growth past the budget is only allocator overhead.
	const slack = 96 << 20
	if after.HeapAlloc > before.HeapAlloc+uint64(maxRecordBytes+slack) {
		t.Fatalf("heap grew %d bytes, want at most %d (budget %d + %d slack)", after.HeapAlloc-before.HeapAlloc, maxRecordBytes+slack, maxRecordBytes, slack)
	}
}

func TestReadCommitsDropsMessageMiddle(t *testing.T) {
	git := requireGit(t)
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	gitCmd(t, repo, "config", "user.email", "t@example.invalid")
	gitCmd(t, repo, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "a.txt")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	base := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	const mid = "MID-MARKER-NOT-A-TRAILER"
	message := strings.Repeat("x", maxMessageHead) + mid + strings.Repeat("y", maxMessageTail) + budgetTrailer
	msgPath := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(msgPath, []byte(message), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "commit", "-q", "--allow-empty", "-F", msgPath)
	head := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	commits, warnings, err := ReadCommits(context.Background(), repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, one commit is under the record budget", warnings)
	}
	if len(commits) != 1 || commits[0].SHA != head {
		t.Fatalf("commits = %+v, want %s", commits, head)
	}
	got := commits[0].Message
	if len(got) != maxMessageHead+maxMessageTail {
		t.Fatalf("len = %d, want %d", len(got), maxMessageHead+maxMessageTail)
	}
	if strings.Contains(got, mid) {
		t.Fatal("middle of the commit message was retained")
	}
	if authors := coAuthors(got); len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com") {
		t.Fatalf("coAuthors = %v", authors)
	}
}

// TestLargeMessagesRSS repeats the reported repro at a smaller count:
// many commits whose messages are a few MiB each. Uncapped, those
// messages dominate RSS. Set TRIPCORD_MEM_REPRO=1 to run it. It is not
// part of the default suite because building the commits and reading
// them takes longer than the other prcontext tests.
func TestLargeMessagesRSS(t *testing.T) {
	if os.Getenv("TRIPCORD_MEM_REPRO") == "" {
		t.Skip("set TRIPCORD_MEM_REPRO=1 to run the large-message RSS repro")
	}
	git := requireGit(t)
	repo := t.TempDir()
	gitCmd(t, repo, "init", "-q", "-b", "main")
	gitCmd(t, repo, "config", "user.email", "t@example.invalid")
	gitCmd(t, repo, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "a.txt")
	gitCmd(t, repo, "commit", "-q", "-m", "init")
	base := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	const (
		n       = 80
		msgSize = 4 << 20
		rssCap  = 384 << 20
	)
	body := strings.Repeat("x", msgSize) + budgetTrailer
	msgPath := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(msgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		gitCmd(t, repo, "commit", "-q", "--allow-empty", "-F", msgPath)
	}
	head := strings.TrimSpace(gitOutput(t, git, repo, "rev-parse", "HEAD"))

	commits, warnings, err := ReadCommits(context.Background(), repo, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != n {
		t.Fatalf("commits = %d, want %d, warnings %v", len(commits), n, warnings)
	}
	var total int
	for _, c := range commits {
		total += len(c.SHA) + len(c.AuthorName) + len(c.AuthorEmail) + len(c.CommitterName) + len(c.CommitterEmail) + len(c.Message)
		if len(c.Message) > maxMessageHead+maxMessageTail {
			t.Fatalf("message len %d exceeds head+tail", len(c.Message))
		}
		authors := coAuthors(c.Message)
		if len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com") {
			t.Fatalf("coAuthors = %v", authors)
		}
	}
	if total > maxRecordBytes {
		t.Fatalf("retained %d bytes, budget %d", total, maxRecordBytes)
	}
	hwm := vmHWM(t)
	t.Logf("retained %d bytes across %d commits; VmHWM %d bytes", total, len(commits), hwm)
	if hwm > rssCap {
		t.Fatalf("VmHWM %d bytes exceeds %d; uncapped 4MiB messages are being retained", hwm, rssCap)
	}
}

func TestBigMessageReaderParses(t *testing.T) {
	commits, limited, err := parseRawMessages(2, maxMessageHead+maxMessageTail+128)
	if err != nil {
		t.Fatal(err)
	}
	if limited || len(commits) != 2 {
		t.Fatalf("limited %v commits %d", limited, len(commits))
	}
	for _, c := range commits {
		if len(c.Message) != maxMessageHead+maxMessageTail {
			t.Fatalf("message len %d", len(c.Message))
		}
		authors := coAuthors(c.Message)
		if len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com") {
			t.Fatalf("coAuthors = %v", authors)
		}
	}
}

// TestSyntheticMessageBudgetRSS streams the reported shape, 800 commits
// with a 4MiB message each, through the parser without storing the
// messages. 800 fits in the 128MiB budget once each message is only its
// head and tail; uncapped, the same input retained about 4.5GiB. It is
// skipped unless TRIPCORD_MEM_REPRO=synthetic, so the default suite does
// not read 3GiB of log output.
func TestSyntheticMessageBudgetRSS(t *testing.T) {
	if os.Getenv("TRIPCORD_MEM_REPRO") != "synthetic" {
		t.Skip("set TRIPCORD_MEM_REPRO=synthetic to stream 800 large commit messages")
	}
	const (
		n       = 800
		msgSize = 4 << 20
		rssCap  = 512 << 20
	)
	commits, limited, err := parseRawMessages(n, msgSize)
	if err != nil {
		t.Fatal(err)
	}
	if limited {
		t.Fatal("limited = true, 800 head+tail messages fit in the record budget")
	}
	if len(commits) != n {
		t.Fatalf("commits = %d, want %d", len(commits), n)
	}
	var total int
	for _, c := range commits {
		total += len(c.SHA) + len(c.AuthorName) + len(c.AuthorEmail) + len(c.CommitterName) + len(c.CommitterEmail) + len(c.Message)
		if len(c.Message) != maxMessageHead+maxMessageTail {
			t.Fatalf("message len %d, want head+tail", len(c.Message))
		}
		authors := coAuthors(c.Message)
		if len(authors) != 1 || !strings.Contains(authors[0], "noreply@anthropic.com") {
			t.Fatalf("coAuthors = %v", authors)
		}
	}
	if total > maxRecordBytes {
		t.Fatalf("retained %d bytes, budget %d", total, maxRecordBytes)
	}
	// 800 * 4MiB uncapped. Retaining the bodies would be far past the budget.
	if total >= n*msgSize/8 {
		t.Fatalf("retained %d bytes, messages were not reduced to head+tail", total)
	}
	hwm := vmHWM(t)
	t.Logf("retained %d bytes across %d commits; VmHWM %d bytes", total, len(commits), hwm)
	if hwm > rssCap {
		t.Fatalf("VmHWM %d bytes exceeds %d", hwm, rssCap)
	}
}

func parseRawMessages(n, size int) ([]Commit, bool, error) {
	var budget recordBudget
	var commits []Commit
	for range n {
		message := strings.Repeat("x", size) + budgetTrailer
		commit, err := parseRawCommit(
			bufio.NewReader(bytes.NewReader(rawCommitObject(message))),
			"0123456789abcdef0123456789abcdef01234567",
			&budget,
		)
		if errors.Is(err, errRecordBudget) {
			return commits, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		commits = append(commits, commit)
		if budget.limited {
			return commits, true, nil
		}
	}
	return commits, budget.limited, nil
}

func rawCommitObject(message string) []byte {
	return []byte("tree 0123456789012345678901234567890123456789\n" +
		"author Ann <ann@example.invalid> 1700000000 +0000\n" +
		"committer Cam <cam@example.invalid> 1700000000 +0000\n\n" +
		message)
}

func vmHWM(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name != "VmHWM" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) != 2 || fields[1] != "kB" {
			t.Fatalf("VmHWM = %q", line)
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return kb << 10
	}
	t.Fatal("VmHWM missing from /proc/self/status")
	return 0
}
