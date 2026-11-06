package githubaction_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	actionlintURL  = "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz"
	actionlintSum  = "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
	actionlintCurl = "curl --retry 5 --retry-all-errors --connect-timeout 10 -fsSL -o \"$archive\" " + actionlintURL

	goLicensesModule = "github.com/google/go-licenses/v2@3e084b0caf710f7bfead967567539214f598c0a2"
)

// checkActionlintDownload pins the v1.7.12 tarball, its checksum, and a
// five-retry curl. The checksum runs before tar extracts the binary and
// before that binary is executed. curl's default delay is left in place:
// it grows between retries and is not applied when the first transfer works.
func checkActionlintDownload(t *testing.T, run string) {
	t.Helper()
	if strings.Contains(run, "${{") {
		t.Fatal("actionlint step interpolates an expression into run")
	}
	for _, want := range []string{
		actionlintCurl,
		actionlintSum,
		"sha256sum -c -",
		"tar -xzf \"$archive\"",
		"\"$RUNNER_TEMP/actionlint\"",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("actionlint step missing %s", want)
		}
	}
	if strings.Contains(run, "--retry-delay") {
		t.Fatal("actionlint curl sets a retry delay; the first success must not sleep and later retries use curl's growing default")
	}
	sum := strings.Index(run, "sha256sum -c -")
	extract := strings.Index(run, "tar -xzf")
	bin := strings.Index(run, "\"$RUNNER_TEMP/actionlint\"")
	if sum < 0 || extract < 0 || bin < 0 || sum > extract || extract > bin {
		t.Fatal("checksum does not run before actionlint is extracted and executed")
	}
	if got := actionlintCurlLine(t, run); got != actionlintCurl {
		t.Fatalf("curl line = %q", got)
	}
}

func TestEmbedActionlintDownloadIsChecksumPinned(t *testing.T) {
	run := stepRun(t, "embed-lint", "actionlint generated workflows")
	checkActionlintDownload(t, run)
	mainRun := stepRun(t, "actionlint", "actionlint")
	if actionlintCurlLine(t, run) != actionlintCurlLine(t, mainRun) {
		t.Fatal("actionlint downloads differ between the lint job and the embed job")
	}
}

func TestToolFetchRetriesStayOnToolFetches(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	retries, allErrors := 0, 0
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		retries += strings.Count(string(data), "--retry 5")
		allErrors += strings.Count(string(data), "--retry-all-errors")
	}
	if retries != 2 || allErrors != 2 {
		t.Fatalf("retry flags = %d and %d, want one pair on each actionlint download", retries, allErrors)
	}
	job := ciJob(t, "licenses")
	for _, step := range seq(t, job["steps"]) {
		parsed := mapping(t, step)
		if strings.Contains(scalar(parsed["uses"]), "actions/cache") || strings.Contains(scalar(parsed["run"]), "actions/cache") {
			t.Fatal("licenses job uses a module cache")
		}
	}
	setup := stepByName(t, job, "Setup Go")
	if scalar(mapping(t, setup["with"])["cache"]) != "false" {
		t.Fatal("licenses setup-go cache is not false")
	}
	install := stepByName(t, job, "Install go-licenses")
	if scalar(install["shell"]) != "bash" {
		t.Fatalf("install shell = %q, want bash", scalar(install["shell"]))
	}
	run := scalar(install["run"])
	for _, want := range []string{
		"set -euo pipefail",
		"module=\"" + goLicensesModule + "\"",
		"go install \"$module\"",
		"attempt=1",
		"delay=1",
		"[ \"$attempt\" -ge 5 ]",
		"sleep \"$delay\"",
		"delay=$((delay * 2))",
		"exit 1",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("go-licenses install missing %s", want)
		}
	}
	if strings.Index(run, "go install \"$module\"") > strings.Index(run, "sleep") {
		t.Fatal("go-licenses install sleeps before the first attempt")
	}
	if strings.Count(run, "go install \"$module\"") != 1 {
		t.Fatalf("go install command appears %d times", strings.Count(run, "go install \"$module\""))
	}
}

func TestGoLicensesInstallAttemptBudget(t *testing.T) {
	run := stepRun(t, "licenses", "Install go-licenses")
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	// fails is how many leading go install calls return non-zero.
	// sleeps is the delay sequence, empty when the first attempt works.
	cases := []struct {
		name  string
		fails int
		sleep []string
		ok    bool
	}{
		{name: "first attempt", fails: 0, ok: true},
		{name: "one failure then success", fails: 1, sleep: []string{"1"}, ok: true},
		{name: "five failures", fails: 5, sleep: []string{"1", "2", "4", "8"}, ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls, sleeps, err := runInstallScript(t, bash, run, tc.fails)
			if tc.ok && err != nil {
				t.Fatalf("install failed: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("five failures exited 0")
			}
			wantCalls := tc.fails
			if tc.ok {
				wantCalls++
			}
			if calls != wantCalls {
				t.Fatalf("go install calls = %d, want %d", calls, wantCalls)
			}
			if strings.Join(sleeps, ",") != strings.Join(tc.sleep, ",") {
				t.Fatalf("sleeps = %q, want %q", sleeps, tc.sleep)
			}
		})
	}
}

func TestActionlintCurlRetryBudget(t *testing.T) {
	line := actionlintCurlLine(t, stepRun(t, "actionlint", "actionlint"))
	curlBin, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal(err)
	}
	// --retry 5 is five retries after the first transfer. A permanent
	// 504 is six requests and a non-zero exit. The wrapper adds
	// --retry-delay 1 so the test does not wait on curl's default
	// backoff; the workflow itself does not set a delay.
	t.Run("first transfer", func(t *testing.T) {
		n, err := runActionlintCurl(t, curlBin, line, 0, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("requests = %d, want 1", n)
		}
	})
	t.Run("one 504", func(t *testing.T) {
		n, err := runActionlintCurl(t, curlBin, line, 1, 8*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Fatalf("requests = %d, want 2", n)
		}
	})
	t.Run("retry budget spent", func(t *testing.T) {
		n, err := runActionlintCurl(t, curlBin, line, -1, 20*time.Second)
		if err == nil {
			t.Fatal("permanent 504 exited 0")
		}
		if n != 6 {
			t.Fatalf("requests = %d, want 6 (1 initial + 5 retries)", n)
		}
	})
}

func runInstallScript(t *testing.T, bash, run string, fails int) (int, []string, error) {
	t.Helper()
	dir := t.TempDir()
	callLog := filepath.Join(dir, "calls")
	sleepLog := filepath.Join(dir, "sleeps")
	writeExec(t, filepath.Join(dir, "go"), fmt.Sprintf(`#!/bin/sh
if [ "$1" != install ] || [ "$2" != %q ] || [ "$#" -ne 2 ]; then
  echo "bad args: $*" >&2
  exit 3
fi
printf '%%s\n' "$*" >> "$CALL_LOG"
count=$(grep -c . "$CALL_LOG")
if [ "$count" -le "$FAILS" ]; then
  exit 1
fi
exit 0
`, goLicensesModule))
	writeExec(t, filepath.Join(dir, "sleep"), `#!/bin/sh
printf '%s\n' "$1" >> "$SLEEP_LOG"
`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "-c", run)
	cmd.Env = []string{
		"PATH=" + dir + ":/usr/bin:/bin",
		"CALL_LOG=" + callLog,
		"SLEEP_LOG=" + sleepLog,
		"FAILS=" + strconv.Itoa(fails),
		"HOME=" + dir,
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("install script timed out, output %s", out)
	}
	if err != nil {
		err = fmt.Errorf("%w: %s", err, out)
	}
	calls := countLines(t, callLog)
	return calls, readLines(sleepLog), err
}

func runActionlintCurl(t *testing.T, curlBin, line string, failFirst int, limit time.Duration) (int, error) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(hits.Add(1))
		if failFirst < 0 || n <= failFirst {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	writeExec(t, filepath.Join(dir, "curl"), fmt.Sprintf("#!/bin/sh\nexec %s --retry-delay 1 \"$@\"\n", shellQuote(curlBin)))
	archive := filepath.Join(dir, "actionlint.tar.gz")
	script := "set -euo pipefail\narchive=" + shellQuote(archive) + "\n" + strings.Replace(line, actionlintURL, srv.URL+"/actionlint.tar.gz", 1) + "\n"
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+dir+":/usr/bin:/bin")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("curl timed out after %s, output %s", limit, out)
	}
	if err != nil {
		err = fmt.Errorf("%w: %s", err, out)
	}
	return int(hits.Load()), err
}

func actionlintCurlLine(t *testing.T, run string) string {
	t.Helper()
	var got string
	for _, line := range strings.Split(run, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "curl ") {
			continue
		}
		if got != "" {
			t.Fatal("actionlint step has two curl commands")
		}
		got = line
	}
	if got == "" {
		t.Fatal("actionlint step has no curl command")
	}
	return got
}

func stepRun(t *testing.T, jobName, stepName string) string {
	t.Helper()
	run := scalar(stepByName(t, ciJob(t, jobName), stepName)["run"])
	if run == "" {
		t.Fatalf("%s/%s has no run script", jobName, stepName)
	}
	return run
}

func ciJob(t *testing.T, id string) map[string]*yaml.Node {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal(readCI(t), &root); err != nil {
		t.Fatal(err)
	}
	return mapping(t, mapping(t, mapping(t, &root)["jobs"])[id])
}

func readCI(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func stepByName(t *testing.T, job map[string]*yaml.Node, name string) map[string]*yaml.Node {
	t.Helper()
	for _, step := range seq(t, job["steps"]) {
		parsed := mapping(t, step)
		if scalar(parsed["name"]) == name {
			return parsed
		}
	}
	t.Fatalf("no step %q", name)
	return nil
}

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	return len(readLines(path))
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := strings.TrimSuffix(string(data), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
