package output

import (
	"slices"
	"strings"
	"testing"
)

// An env assignment whose name contains a credential word anywhere, not
// only at its end, is redacted: SECRET_KEY, AWS_SECRET_ACCESS_KEY, and
// DB_PWD hold secrets just as GITHUB_TOKEN does.
func TestCredentialNamedAssignmentsAreRedacted(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want, removed string }{
		{"docker run -e SECRET_KEY=SKVAL img", "docker run -e SECRET_KEY=[REDACTED] img", "SKVAL"},
		{"docker run -e AWS_SECRET_ACCESS_KEY=AWSVAL img", "docker run -e AWS_SECRET_ACCESS_KEY=[REDACTED] img", "AWSVAL"},
		{"AWS_ACCESS_KEY=AKVAL aws s3 ls", "AWS_ACCESS_KEY=[REDACTED] aws s3 ls", "AKVAL"},
		{"export DB_PWD=PWDVAL", "export DB_PWD=[REDACTED]", "PWDVAL"},
		{"MYSQL_PASSWD=PASSWDVAL mysql", "MYSQL_PASSWD=[REDACTED] mysql", "PASSWDVAL"},
		{"STRIPE_APIKEY=APIKEYVAL node app", "STRIPE_APIKEY=[REDACTED] node app", "APIKEYVAL"},
		{"SSH_PRIVATE_KEY='PKVAL' deploy", "SSH_PRIVATE_KEY='[REDACTED]' deploy", "PKVAL"},
		{"GCP_CREDENTIALS=CREDVAL gcloud", "GCP_CREDENTIALS=[REDACTED] gcloud", "CREDVAL"},
		{"DJANGO_SECRETKEY=GLUEDVAL run", "DJANGO_SECRETKEY=[REDACTED] run", "GLUEDVAL"},
		{"API_KEY_V2=V2VAL run", "API_KEY_V2=[REDACTED] run", "V2VAL"},
		{"TOKEN_TTL=30,SECRET_KEY=LATERVAL", "TOKEN_TTL=30,SECRET_KEY=[REDACTED]", "LATERVAL"},
		{"PRIVATE_KEY=BAREPK deploy", "PRIVATE_KEY=[REDACTED] deploy", "BAREPK"},
		{"docker run -e DB_PASS=DBPASSVAL img", "docker run -e DB_PASS=[REDACTED] img", "DBPASSVAL"},
		{"SMTP_PASS='SMTPVAL' mailer", "SMTP_PASS='[REDACTED]' mailer", "SMTPVAL"},
		{"SECRET_KEY: YAMLVAL", "SECRET_KEY: [REDACTED]", "YAMLVAL"},
		{"DB_PASS: YAMLPASS", "DB_PASS: [REDACTED]", "YAMLPASS"},
		{"env: {AWS_SECRET_ACCESS_KEY: FLOWVAL}", "env: {AWS_SECRET_ACCESS_KEY: [REDACTED]}", "FLOWVAL"},
	}
	for _, tc := range cases {
		if got := DefaultRedactor(tc.in); got != tc.want {
			t.Errorf("DefaultRedactor(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got, removed := RedactCommand(tc.in); got != tc.want || !slices.Equal(removed, []string{tc.removed}) {
			t.Errorf("RedactCommand(%q) = %q, %q; want %q, [%q]", tc.in, got, removed, tc.want, tc.removed)
		}
	}
}

// Over-redaction guards, each a documented judgement:
//   - SECRET_KEY_FILE, TOKEN_PATH, and GITHUB_TOKEN_ENV_VAR name where a
//     secret lives, not the secret; the path or variable name is evidence
//     a reviewer needs, and the file's content is not in the text.
//   - TOKEN_TTL=30 and SECRET_NAME=db-creds are metadata about a
//     credential (a lifetime, a reference), not its value.
//   - PWD and OLDPWD are the shell's working directories; "pwd" counts
//     only after another segment (DB_PWD).
//   - TOKENIZER and SECRETARY merely start with a credential word, and
//     BYPASS and PASS_THROUGH are not a "pass" after another segment.
func TestCredentialMetadataAssignmentsAreKept(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"BYPASS=1 make",
		"PASS_THROUGH=1 make",
		"SECRET_KEY_FILE=/run/secrets/key app",
		"docker run -e TOKEN_PATH=/var/run/token img",
		"GITHUB_TOKEN_ENV_VAR=GH_TOKEN tool",
		"TOKEN_TTL=30 app",
		"SECRET_NAME=db-creds kubectl apply",
		"PWD=/tmp make",
		"OLDPWD=/home/x cd -",
		"TOKENIZER=gpt2 train",
		"SECRETARY=bob mail",
		"SECRET_KEY_FILE: /run/secrets/key",
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
		if got, removed := RedactCommand(in); got != in || len(removed) != 0 {
			t.Errorf("RedactCommand(%q) = %q, %q; want unchanged", in, got, removed)
		}
	}
}

// gh auth login --with-token is a boolean flag (the token comes from
// stdin), not a secret flag: neither it, its "=true" spelling, nor the
// word after it is redacted, while a real token piped in is still caught
// by the token-shape patterns.
func TestWithTokenIsABooleanFlag(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"gh auth login --with-token < token.txt",
		"gh auth login --with-token <token.txt",
		"echo $GH_TOKEN | gh auth login --with-token",
		"gh auth login --with-token --hostname ghe.example",
		"gh auth login --with-token=true",
		"gh auth login --hostname ghe.example --with-token",
	} {
		if got := DefaultRedactor(in); got != in {
			t.Errorf("DefaultRedactor(%q) = %q, want unchanged", in, got)
		}
		if got, removed := RedactCommand(in); got != in || len(removed) != 0 {
			t.Errorf("RedactCommand(%q) = %q, %q; want unchanged", in, got, removed)
		}
	}
	in := "echo ghp_abcdefghijklmnopqrstuvwxyz0123456789 | gh auth login --with-token"
	if got := DefaultRedactor(in); strings.Contains(got, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Errorf("DefaultRedactor(%q) = %q, leaked the piped token", in, got)
	}
}

func TestCredentialName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"SECRET_KEY": true, "AWS_SECRET_ACCESS_KEY": true, "aws_access_key_id": true,
		"GITHUB_TOKEN": true, "_authToken": true, "PGPASSWORD": true, "DB_PWD": true,
		"X-Api-Key": true, "PRIVATE_KEY": true, "credentials": true, "client-secrets": true,
		"DB_PASS": true, "redis-pass": true,
		"SECRET_KEY_FILE": false, "TOKEN_TTL": false, "PWD": false, "OLDPWD": false,
		"TOKENIZER": false, "SECRETARY": false, "MONKEY": false, "KEY": false, "": false,
		"BYPASS": false, "PASS": false, "--with-token": false,
	} {
		if got := CredentialName(name); got != want {
			t.Errorf("CredentialName(%q) = %v, want %v", name, got, want)
		}
	}
}
