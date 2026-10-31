package kit

import (
	"slices"
	"testing"

	"github.com/vgmartinez/tripcord/internal/model"
	"github.com/vgmartinez/tripcord/internal/output"
)

// Sanitize and output.DefaultRedactor share one table: a command is
// redacted at the source exactly as the output side would redact it,
// and a command the output side leaves alone is unchanged with nothing
// recorded for the key discriminator.
func TestSanitizeMatchesOutputRedactor(t *testing.T) {
	t.Parallel()
	redacted := []string{
		"curl --proxy-user bob:PROXYPASS https://x",
		"sshpass -pSSHGLUED ssh host",
		"openssl enc -aes-256-cbc -K 0011HEXKEY -in f",
		"openssl rsa -passin pass:PASSIN -in k.pem",
		"redis-cli --pass REDISLONG ping",
		`cli "--token" QUOTEDFLAG`,
		"aws configure set --secret-access-key AWSSAK",
		"docker run --rm img vercel deploy -t DOCKERREMOTE",
		"x=$(openssl enc -k SUBK)",
		"(cli --token PARENTOK)",
		"cli --token='-Q'",
		"secret: foo && run",
		"docker run -e SECRET_KEY=ENVSK img",
		"docker run -e AWS_SECRET_ACCESS_KEY=ENVAWS img",
		"DB_PWD=ENVPWD psql",
		`echo "token: PXC5" > .env`,
		"echo 'password: PXC6' >> config.yml",
		"printf 'api_key: PXC8'",
		"http example.com X-Api-Key:PXC7",
		"http example.com 'X-API-Token:PXC7B'",
		`echo "db password: PXC9" > .env`,
		`echo "my token: PXC10"`,
		"echo 'user: a password: PXC11'",
		`echo "export A=1; token: PXC12"`,
		"http h x-api-key:PXC13",
		"http h api_key:PXC14",
		"echo -e 'token: PXC15'",
		"sh -c 'echo token: PXC16'",
		"echo password: PXC17 > f",
		"echo secret: foo && run",
		"echo -e --token PXC21",
	}
	for _, in := range redacted {
		got := source(model.ScopeRepo, "a").Sanitize(in)
		if want := output.DefaultRedactor(in); got.Value != want || want == in || len(got.Removed) == 0 {
			t.Errorf("Sanitize(%q) = %q, %q; output side = %q", in, got.Value, got.Removed, want)
		}
	}
	for _, in := range []string{
		"git commit -m 'fix token: handling'",
		"grep -e --token file",
		"cli --token=",
		"grep -e 'token: x' file",
		"make -C /opt/fly -t all",
		"security find-generic-password -w",
		"docker run -e SECRET_KEY_FILE=/run/secrets/k img",
		"TOKEN_TTL=30 app",
	} {
		if got := source(model.ScopeRepo, "a").Sanitize(in); got.Value != in || len(got.Removed) != 0 {
			t.Errorf("Sanitize(%q) = %q, %q; want unchanged, nothing removed", in, got.Value, got.Removed)
		}
	}
}

func TestSanitizeQuotesAgree(t *testing.T) {
	t.Parallel()
	got := source(model.ScopeRepo, "a").Sanitize("cli --token='-Q' run")
	if got.Value != "cli --token='[REDACTED]' run" || !slices.Equal(got.Removed, []string{"-Q"}) {
		t.Fatalf("Sanitize = %q, %q", got.Value, got.Removed)
	}
}
