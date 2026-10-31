package output

import (
	"slices"
	"strings"
	"testing"
)

func TestRedactCommandMoreCredentialFlags(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want, removed string }{
		{"curl --proxy-user bob:PROXYPASS https://x", "curl --proxy-user [REDACTED] https://x", "bob:PROXYPASS"},
		{"sshpass -pSSHGLUED ssh host", "sshpass -p[REDACTED] ssh host", "SSHGLUED"},
		{"openssl enc -aes-256-cbc -K 0011HEXKEY -iv 00 -in f", "openssl enc -aes-256-cbc -K [REDACTED] -iv 00 -in f", "0011HEXKEY"},
		{"openssl rsa -passin pass:PASSIN -in k.pem", "openssl rsa -passin pass:[REDACTED] -in k.pem", "PASSIN"},
		{"openssl pkcs12 -export -pass pass:PASSPASS", "openssl pkcs12 -export -pass pass:[REDACTED]", "PASSPASS"},
		{"openssl genrsa -passout 'pass:PASSOUT' 2048", "openssl genrsa -passout 'pass:[REDACTED]' 2048", "PASSOUT"},
		{"redis-cli --pass REDISLONG ping", "redis-cli --pass [REDACTED] ping", "REDISLONG"},
		{"git clone https://user:pa/SLASHPASS@host/r", "git clone https://[REDACTED]@host/r", "user:pa/SLASHPASS"},
		{"aws configure --secret-access-key AWSSAK", "aws configure --secret-access-key [REDACTED]", "AWSSAK"},
	}
	for _, tc := range cases {
		got, removed := RedactCommand(tc.in)
		if got != tc.want || !slices.Contains(removed, tc.removed) {
			t.Errorf("RedactCommand(%q) = %q, %q; want %q with %q removed", tc.in, got, removed, tc.want, tc.removed)
		}
		if def := DefaultRedactor(tc.in); def != tc.want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", tc.in, def, tc.want)
		}
	}
	for _, in := range []string{
		"openssl rsa -passin env:PASSVAR -in k.pem",
		"openssl rsa -passin file:/run/pw -in k.pem",
		"openssl rsa -passin stdin",
		"curl https://host:8080/x@y",
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
	}
	argv := []string{"openssl", "rsa", "-passin", "pass:ARGVPASS", "-K", "ARGVHEX"}
	got, removed := RedactToolArgv(argv)
	if want := []string{"openssl", "rsa", "-passin", "pass:[REDACTED]", "-K", "[REDACTED]"}; !slices.Equal(got, want) || !slices.Equal(removed, []string{"ARGVHEX", "ARGVPASS"}) {
		t.Errorf("RedactToolArgv(%q) = %q, %q", argv, got, removed)
	}
	argv = []string{"sshpass", "-pARGVGLUED", "ssh", "host"}
	if got, _ := RedactToolArgv(argv); got[1] != "-p[REDACTED]" {
		t.Errorf("RedactToolArgv(%q) = %q", argv, got)
	}
}

// The command a docker container or an ssh session runs is scanned like
// any other command: the tool word activates its flags wherever it sits.
func TestRedactCommandScansRemoteCommands(t *testing.T) {
	t.Parallel()
	leaks := map[string]string{
		"docker run --rm img vercel deploy -t DOCKERREMOTE":        "DOCKERREMOTE",
		`docker run -e X=1 img sh -c "mysql -pDOCKERMYSQL db"`:     "DOCKERMYSQL",
		"docker exec -it ctr redis-cli --pass DOCKERREDIS":         "DOCKERREDIS",
		"ssh host 'openssl enc -k SSHREMOTE'":                      "SSHREMOTE",
		"ssh -i key host redis-cli -a SSHREDIS":                    "SSHREDIS",
		"ssh host sshpass -pSSHGLUEDREMOTE ssh inner":              "SSHGLUEDREMOTE",
		"ssh -t host 'openssl rsa -passin pass:SSHPASSIN -in k'":   "SSHPASSIN",
		"docker run img curl --proxy-user u:DOCKERPROXY https://x": "DOCKERPROXY",
		"ssh host -- docker login -u bob -p SSHDOCKERLOGIN reg.io": "SSHDOCKERLOGIN",
	}
	for in, secret := range leaks {
		if got := DefaultRedactor(in); strings.Contains(got, secret) {
			t.Errorf("DefaultRedactor(%q) = %q leaks %q", in, got, secret)
		}
		if got, _ := RedactCommand(in); strings.Contains(got, secret) {
			t.Errorf("RedactCommand(%q) = %q leaks %q", in, got, secret)
		}
	}
	for _, argv := range [][]string{
		{"docker", "run", "--rm", "img", "vercel", "-t", "ARGVREMOTE"},
		{"ssh", "host", "openssl", "enc", "-k", "ARGVREMOTE"},
		{"ssh", "host", "redis-cli", "--pass", "ARGVREMOTE"},
	} {
		if got, _ := RedactToolArgv(argv); slices.Contains(got, "ARGVREMOTE") {
			t.Errorf("RedactToolArgv(%q) = %q", argv, got)
		}
	}
}
