# Installation

tripcord is one static binary. Homebrew, npm, and PyPI install that
same release binary; none of them builds tripcord. There is no Docker
image.

| Method | Command | Platforms |
| --- | --- | --- |
| [Homebrew](#with-homebrew) | `brew install vgmartinez/tap/tripcord` | macOS, Linux |
| [npm](#with-npm) | `npx tripcord scan .` | macOS, Linux, Windows |
| [PyPI](#with-pypi) | `uvx tripcord scan .` or `pip install tripcord` | macOS, Linux, Windows |
| [Release archive](#from-a-release) | download and verify by hand | macOS, Linux, Windows |
| [`go install`](#with-go-install) | builds from source | any Go platform |

Every package covers amd64 (x86-64) and arm64. Each package's version is
the release tag without the `v`: release `v0.1.0` is Homebrew, npm, and
PyPI version `0.1.0`.

## With Homebrew

```sh
brew install vgmartinez/tap/tripcord
tripcord --version
```

The formula lives in
[vgmartinez/homebrew-tap](https://github.com/vgmartinez/homebrew-tap).
It downloads the release archive for your OS and CPU and Homebrew checks
it against the sha256 in the formula, which is copied from the release's
`SHA256SUMS`. When a release is published, this repository's `homebrew`
workflow checks the archives and their build provenance, regenerates the
formula, and opens a pull request on the tap; the formula changes when
that pull request is merged.

## With npm

```sh
npx tripcord scan .
# or
npm install -g tripcord
```

The `tripcord` npm package has no dependencies and no install script.
It ships a small Node.js launcher and the release's `SHA256SUMS`. On
first run the launcher downloads the archive for your platform from
`https://github.com/vgmartinez/tripcord/releases/download/v<version>/`,
which GitHub redirects to `release-assets.githubusercontent.com`. It
checks the archive's sha256 against the bundled `SHA256SUMS` and runs
nothing on a mismatch. The binary is cached in `$TRIPCORD_CACHE_DIR`,
or by default `$XDG_CACHE_HOME/tripcord` (`~/.cache/tripcord`) on Linux,
`~/Library/Caches/tripcord` on macOS, and
`%LOCALAPPDATA%\tripcord\cache` on Windows, and later runs make no
network request. There is no telemetry. Any platform other than Linux,
macOS, or Windows on x64 or arm64 gets an error that names it.

The package is published by the `npm` workflow with npm trusted
publishing, so `npm audit signatures` and the package page show its
provenance: the workflow run that published it.

## With PyPI

```sh
uvx tripcord scan .
# or
pip install tripcord
```

Each wheel bundles the unchanged binary from one release archive and a
`tripcord` command that runs it. The `pypi` workflow checks the
archives against `SHA256SUMS` and their build provenance before it
repackages them, and publishes with PyPI trusted publishing. The wheels
are tagged for Linux on glibc 2.17 or newer and on musl
(`manylinux_2_17`, `musllinux_1_1`), for the minimum macOS version the
binary itself declares (macOS 13 for v0.1.0), and for Windows. There is
no source distribution: on any other platform pip reports that no
matching distribution was found.

## From a release

Each release on the
[Releases](https://github.com/vgmartinez/tripcord/releases) page has six
archives and a `SHA256SUMS` file:

| Platform | Archive |
| --- | --- |
| Linux x86-64 | `tripcord_<version>_linux_amd64.tar.gz` |
| Linux arm64 | `tripcord_<version>_linux_arm64.tar.gz` |
| macOS x86-64 | `tripcord_<version>_darwin_amd64.tar.gz` |
| macOS arm64 | `tripcord_<version>_darwin_arm64.tar.gz` |
| Windows x86-64 | `tripcord_<version>_windows_amd64.zip` |
| Windows arm64 | `tripcord_<version>_windows_arm64.zip` |

Each archive holds the `tripcord` binary (`tripcord.exe` on Windows),
`LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES`. `<version>` has no
leading `v`: the `v0.1.0` release has `tripcord_0.1.0_linux_amd64.tar.gz`.

Download an archive and `SHA256SUMS`, check the checksum, and verify
the build provenance with the [GitHub CLI](https://cli.github.com/):

```sh
tag=v0.1.0
file="tripcord_${tag#v}_linux_amd64.tar.gz"
gh release download "$tag" --repo vgmartinez/tripcord --pattern "$file" --pattern SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify "$file" --repo vgmartinez/tripcord
tar -xzf "$file" tripcord
./tripcord --version
```

`gh attestation verify` needs an authenticated GitHub CLI, even for
this public repository. Run `gh auth login` once, or set `GH_TOKEN`
(in GitHub Actions, `GH_TOKEN: ${{ github.token }}` is enough). The
checksum step works without it. `gh release download` itself works
without logging in. On a machine without `gh`, download with
`curl -LO https://github.com/vgmartinez/tripcord/releases/download/<tag>/<file>`
instead; attestation verification still needs `gh` and a token.

`sha256sum -c SHA256SUMS` checks every archive; `--ignore-missing`
skips the ones you did not download. On macOS, use
`shasum -a 256 -c SHA256SUMS --ignore-missing`. `gh attestation verify`
checks that the archive was built by this repository's `release`
workflow from the tagged commit. `tripcord --version` prints the tag
and the commit, for example `v0.1.0 (commit <sha>)`.

### Rebuilding a release

The release build is reproducible: the same commit and Go toolchain
give byte-identical archives. To check a release against its source:

```sh
git clone https://github.com/vgmartinez/tripcord.git
cd tripcord
git checkout v0.1.0
scripts/release-build.sh build "$PWD/../dist" v0.1.0 \
  linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
scripts/release-build.sh sums "$PWD/../dist"
```

Then compare `../dist/SHA256SUMS` with the release's `SHA256SUMS`. The
script needs the Go version in `go.mod`, GNU `tar`, `gzip`, and `zip`,
and a clean worktree.

## With `go install`

With Go 1.27.3 or newer:

```sh
go install github.com/vgmartinez/tripcord/cmd/tripcord@main
```

`@v0.1.0` installs that release's source instead. Either way,
`tripcord version` prints `dev`: the version and commit are only set at
link time, by the release build
([Development](development.md#module-and-version)).

## From a checkout

```sh
git clone https://github.com/vgmartinez/tripcord.git
cd tripcord
CGO_ENABLED=0 go build -trimpath -o tripcord ./cmd/tripcord
```

## In GitHub Actions

The [GitHub Action](github-action.md) and the reusable workflows build
tripcord from source at the commit they pin. They do not download a
release archive.
