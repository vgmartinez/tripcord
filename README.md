# tripcord

Private pre-release.

tripcord is an Apache-2.0 command-line tool for coding-agent security.
It will scan agent configuration, look for secrets in context and transcripts,
and support local forensics. This build only implements `help` and `version`.

```sh
make build   # CGO_ENABLED=0 binary at bin/tripcord
make test
make lint
make fmt
```

`main.version` is set with `-ldflags "-X main.version=..."`.

Licensed under Apache-2.0. See [LICENSE](LICENSE).

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/README.md](docs/README.md).
