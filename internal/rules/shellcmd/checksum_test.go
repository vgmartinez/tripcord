package shellcmd

import (
	"strings"
	"testing"
)

func TestChecksumScript(t *testing.T) {
	const (
		u     = "https://get.example.invalid/i.sh"
		fetch = "curl -fsSLo i.sh " + u
		check = "sha256sum -c i.sh.sha256"
		entry = "echo '" + sum + "  i.sh' | sha256sum -c -"
	)
	for _, tc := range []struct {
		script string
		want   bool
	}{
		// Each allowed form.
		{fetch + " && " + check + " && sh i.sh", true},
		{"curl --fail --silent --location --output i.sh " + u + " && " + check + " && bash i.sh", true},
		{"curl -fsSL -o i.sh --retry 3 " + u + " && " + check + " && sh i.sh", true},
		{"wget -qO i.sh " + u + " && " + check + " && sh i.sh", true},
		{"wget -q --output-document=i.sh " + u + " && " + check + " && sh i.sh", true},
		{fetch + " && shasum -a 256 -c i.sh.sha256 && sh i.sh", true},
		{fetch + " && " + entry + " && sh i.sh", true},
		{fetch + " && echo \"" + sum + "  i.sh\" | sha256sum -c && sh i.sh", true},
		{fetch + " && printf '" + sum + "  i.sh\\n' | sha256sum --check - && sh i.sh", true},
		{fetch + " && echo '" + sum + " *i.sh' | shasum -a 256 -c && sh i.sh", true},
		{"set -e\n" + fetch + "\n" + check + "\nsh i.sh\n", true},
		{"set -eu; " + fetch + "; " + entry + "; sh i.sh", true},
		{"set -e; set -euo pipefail\n" + fetch + "\n" + check + "\nsh i.sh", true},
		{"set -o errexit; " + fetch + "; " + check + "; sh i.sh", true},
		{"set -eo pipefail; " + fetch + "; " + check + "; sh i.sh --prefix /usr/local", true},
		{"mkdir tools && " + fetch + " && chmod +x i.sh && " + check + " && sh i.sh && rm i.sh", true},
		{"# install the tool\n" + fetch + " && " + check + " && sh i.sh # done", true},
		{fetch + " &&\n  " + check + " &&\n  sh i.sh", true},
		{"curl -fsSLo t.tgz " + u + " && sha256sum -c t.tgz.sha256", false},
		{"set -e; curl -fsSLo t.tgz " + u + " && sha256sum -c t.tgz.sha256 && mkdir out", false},
		{fetch + " && curl -fsSLo j.sh " + u + " && " + check + " && sh i.sh && sh j.sh", true},

		// set -e detection (B3).
		{"echo set -e; " + fetch + "; " + check + "; sh i.sh", false},
		{": set -e; " + fetch + "; " + check + "; sh i.sh", false},
		{"true set -euo pipefail; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; \\set +e; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; s=set; $s +e; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; shopt -u -o errexit; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; set(){ :; }; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; trap 'sh i.sh' EXIT; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; trap 'sh i.sh' ERR; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; sha256sum(){ :; }; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; set +e; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; eval x; " + fetch + "; " + check + "; sh i.sh", false},
		{"set -e; " + fetch + "; " + check + "; set -e; sh i.sh", false},
		{fetch + "; set -e; " + check + "; sh i.sh", false},
		{"set -e && " + fetch + "; " + check + "; sh i.sh", false},
		{"set -x; " + fetch + "; " + check + "; sh i.sh", false},
		{"'set' -e; " + fetch + "; " + check + "; sh i.sh", false},

		// The echo entry (B4).
		{fetch + " && echo 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /dev/null' | sha256sum -c && sh i.sh", false},
		{fetch + " && echo '" + sum + "  other.sh' | sha256sum -c - && sh i.sh", false},
		{fetch + " && echo '" + sum + "  -' | sha256sum -c - && sh i.sh", false},
		{fetch + " && echo '" + sum + "  i.sh\n" + sum + "  j.sh' | sha256sum -c - && sh i.sh", false},
		{fetch + " && echo '" + sum[:63] + "  i.sh' | sha256sum -c - && sh i.sh", false},
		{fetch + " && echo '" + sum + " i.sh' | sha256sum -c - && sh i.sh", false},
		{fetch + " && echo -e '" + sum + "  i.sh' | sha256sum -c - && sh i.sh", false},
		{fetch + " && echo '" + sum + "  i.sh\\c' | sha256sum -c - && sh i.sh", false},
		{fetch + " && printf '%s  i.sh' " + sum + " | sha256sum -c - && sh i.sh", false},
		{fetch + " && cat sums | sha256sum -c - && sh i.sh", false},
		{fetch + " && " + entry + " | cat && sh i.sh", false},
		{fetch + " && sha256sum -c - && sh i.sh", false},
		{fetch + " && sha256sum -c /dev/stdin && sh i.sh", false},

		// Ordering and guards.
		{fetch + "; " + check + "; sh i.sh", false},
		{fetch + " && " + check + "; sh i.sh", false},
		{"set -e; " + fetch + "; " + check + " && true; sh i.sh", false},
		{"set -e; " + fetch + " && " + check + " && mkdir x; sh i.sh", false},
		{fetch + " && sh i.sh && " + check, false},
		{check + " && " + fetch + " && sh i.sh", false},
		{fetch + " && " + check + " && " + fetch + " && sh i.sh", false},
		{fetch, false},
		{fetch + " && sh i.sh", false},
		{fetch + " && " + check + " && sh other.sh", false},
		{fetch + " && " + check + " && cd sub && sh i.sh", false},
		{"curl -fsSLo i.sh.sha256 " + u + " && " + fetch + " && " + check + " && sh i.sh", false},
		{"set -e; " + fetch + "; " + check + " & sh i.sh", false},
		{fetch + " && " + check + " || true; sh i.sh", false},
		{fetch + " && " + check + " && sh i.sh;;", false},

		// Fetches the grammar does not credit.
		{"curl -fsSLO " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSL " + u + " -o i.sh -o j.sh && " + check + " && sh i.sh", false},
		{"curl -fsSLo i.sh " + u + " " + u + " && " + check + " && sh i.sh", false},
		{"curl -K cfg -o i.sh " + u + " && " + check + " && sh i.sh", false},
		{"curl -o i.sh " + u + " --next -o j.sh " + u + " && " + check + " && sh i.sh", false},
		{"curl -o i.sh file:///etc/passwd && " + check + " && sh i.sh", false},
		{"curl -fsSLo sha256sum " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo /usr/local/bin/sha256sum " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo .curlrc " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo curlrc " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo /home/runner/.config/curlrc " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo ../../../.config/curlrc " + u + " && " + check + " && sh i.sh", false},
		{"cd /home/runner; curl -fsSLo .config/curlrc " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo /etc/ld.so.preload " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo - " + u + " && " + check + " && sh i.sh", false},
		{"wget -O - " + u + " && " + check + " && sh i.sh", false},
		{"wget -i list -O i.sh && " + check + " && sh i.sh", false},
		{"/usr/bin/curl -fsSLo i.sh " + u + " && " + check + " && sh i.sh", false},
		{"c\\url -fsSLo i.sh " + u + " && " + check + " && sh i.sh", false},
		{"\"curl\" -fsSLo i.sh " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo \"$F\" " + u + " && " + check + " && sh \"$F\"", false},

		// Other commands and syntax.
		{"export PATH=./bin; " + fetch + " && " + check + " && sh i.sh", false},
		{"export OPENSSL_CONF=p.cnf; " + fetch + " && " + check + " && sh i.sh", false},
		{"export OPENSSL_MODULES=providers; " + fetch + " && " + check + " && sh i.sh", false},
		{"export OPENSSL_ENGINES=engines; " + fetch + " && " + check + " && sh i.sh", false},
		{"export LOCPATH=locale; " + fetch + " && " + check + " && sh i.sh", false},
		{"export NLSPATH=messages; " + fetch + " && " + check + " && sh i.sh", false},
		{"export SSL_CERT_FILE=cert.pem; " + fetch + " && " + check + " && sh i.sh", false},
		{"https_proxy=http://proxy; " + fetch + " && " + check + " && sh i.sh", false},
		{"TMPDIR=tmp; " + fetch + " && " + check + " && sh i.sh", false},
		{"MALLOC_PRELOAD=x.so; " + fetch + " && " + check + " && sh i.sh", false},
		{"GIT_CONFIG=x; " + fetch + " && " + check + " && sh i.sh", false},
		{"PROMPT_COMMAND=x; " + fetch + " && " + check + " && sh i.sh", false},
		{"BASH_ENV=evil.sh; " + fetch + " && " + check + " && bash i.sh", false},
		{"export LD_PRELOAD=x.so; " + fetch + " && " + check + " && sh i.sh", false},
		{"PERL5OPT=-Mx; " + fetch + " && shasum -a 256 -c s && sh i.sh", false},
		{"FOO=1 " + fetch + " && " + check + " && sh i.sh", false},
		{"export -f x; " + fetch + " && " + check + " && sh i.sh", false},
		{"alias sha256sum=true; " + fetch + " && " + check + " && sh i.sh", false},
		{"source env.sh; " + fetch + " && " + check + " && sh i.sh", false},
		{". ./env.sh; " + fetch + " && " + check + " && sh i.sh", false},
		{"exec 3>&1; " + fetch + " && " + check + " && sh i.sh", false},
		{"(" + fetch + " && " + check + " && sh i.sh)", false},
		{"cd tools; " + fetch + " && " + check + " && sh i.sh", false},
		{"mkdir ../tools; " + fetch + " && " + check + " && sh i.sh", false},
		{"chmod 0644 i.sh; " + fetch + " && " + check + " && sh i.sh", false},
		{"chmod -R +x i.sh; " + fetch + " && " + check + " && sh i.sh", false},
		{"rm -f i.sh; " + fetch + " && " + check + " && sh i.sh", false},
		{"rm i.sh; " + fetch + " && " + check + " && sh i.sh", true},
		{"{ " + fetch + "; } && " + check + " && sh i.sh", false},
		{"if true; then " + fetch + "; fi && " + check + " && sh i.sh", false},
		{fetch + " && " + check + " && sh i.sh > log", false},
		{fetch + " && " + check + " && sh -x i.sh", false},
		{fetch + " && " + check + " && sh $(echo i.sh)", false},
		{fetch + " && " + check + " && sh `echo i.sh`", false},
		{fetch + " && " + check + " && sh i.s*", false},
		{fetch + " && " + check + " && npm ci", false},
		{fetch + " && " + check + " && ./i.sh", false},
		{"curl -fsSLo p.cnf " + u + " && " + fetch + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo i.sh " + u + " && curl -fsSLo i.sh.sha256 " + u + " && " + check + " && sh i.sh", false},

		// A sums file is never fetched or run (C, D).
		{"curl -o i.sha " + u + "; curl -o i.sh " + u + "; sha256sum -c i.sha; sh i.sh", false},
		{"set -e; curl -o i.sha " + u + "; curl -o i.sh " + u + "; sha256sum -c i.sha; sh i.sh", false},
		{"curl -o i.sha " + u + " && curl -o i.sh " + u + " && sha256sum -c i.sha && sh i.sh", false},
		{"set -e; curl -o i.sh " + u + "; sha256sum -c i.sha; sh i.sh; curl -o i.sha " + u, false},
		{"curl -o i.sha " + u + " && curl -o i.sh " + u + " && sha256sum -c i.sha && sh i.sha", false},
		{"set -e; curl -o i.sh " + u + "; sha256sum -c i.sh; sh i.sh", false},
		{"curl -o i.sh " + u + " && sha256sum -c i.sh && sh i.sh", false},
		{"curl -o i.sh " + u + " && sha256sum -c I.SH && sh i.sh", false},
		{"curl -o I.SHA " + u + " && curl -o i.sh " + u + " && sha256sum -c i.sha && sh i.sh", false},
		{fetch + " && sha256sum -c i.sha && " + entry + " && sh i.sh && sh i.sha", false},

		// Options and case.
		{"curl -fsSLo -q " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSL -o -- " + u + " && " + check + " && sh i.sh", false},
		{fetch + " && sha256sum -c -q && sh i.sh", false},
		{fetch + " && sha256sum -c -- && sh i.sh", false},
		{fetch + " && echo '" + sum + "  -q' | sha256sum -c && sh i.sh", false},
		{"curl -fsSLo CURLRC " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo _NetRC " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo SH " + u + " && " + check + " && sh i.sh", false},
		{"curl -fsSLo Sha256Sum " + u + " && " + check + " && sh i.sh", false},
		{fetch + " && " + check + " && sh i.sh\r\n", false},
		{fetch + " && " + check + " && sh 'i.sh", false},
		{fetch + " && " + check + " && sh \"i$x.sh\"", false},
		{fetch + " && " + check + " &&", false},
		{fetch + " && " + check + " && | sh i.sh", false},
		{"", false},
	} {
		if got := checksumScript(tc.script); got != tc.want {
			t.Errorf("checksumScript(%q) = %v, want %v", tc.script, got, tc.want)
		}
	}
}

func TestChecksumScriptCopilotPrefix(t *testing.T) {
	run := "curl -fsSLo t.sh https://get.example.invalid/t.sh\necho \"" + sum + "  t.sh\" | sha256sum -c\nsh t.sh\n"
	if !checksumScript("set -e; " + run) {
		t.Fatal("Copilot's errexit prefix is not a leading set -e")
	}
	if checksumScript(run) {
		t.Fatal("a check on its own line counts without errexit")
	}
	if !strings.Contains(sum, "ab") {
		t.Fatal("bad sum")
	}
}
