# cert — a certificate and X.509 swiss‑army knife

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/kisom/cert/tree/master.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/kisom/cert/tree/master)

cert is a small command‑line tool for inspecting and working with X.509/TLS
certificates and connections. It consolidates several utilities from
[goutils](https://github.com/kisom/goutils/) into a single, ergonomic CLI.

AI notes:

+ None of the code has been written with AI.
+ The docs are currently largely AI-generated while I work on the tool 
  itself.

Overview
--------

The `cert` binary provides subcommands to:

- Connect to TLS endpoints and print connection details (version, cipher, peers).
- Fetch and display certificate chains or dump certificate files.
- Save a remote host's full certificate chain to PEM.
- Compute and compare Subject Key Identifiers (SKIs) for keys/certs.
- Verify certificate chains using optional custom root/intermediate bundles and
  optional revocation checks.


Stack and Tooling
-----------------

- Language: Go (module name: `cert`, Go toolchain declared in `go.mod`).
- CLI framework: [spf13/cobra]
- Configuration: [spf13/viper] (flags + environment + optional YAML config)
- Dependencies: vendored via Go modules (`go.mod`, `go.sum`).
- Packaging/Release: [goreleaser] (see `.goreleaser.yaml`).
- CI: CircleCI (see badge above and `.circleci/config.yml`).


Requirements
------------

- Go toolchain installed. The module currently declares:
  - go 1.25 in `go.mod` (use a compatible or newer Go version).
- Network access if connecting to remote TLS endpoints.


Installation
------------

- Build a local binary:

```
  git clone https://github.com/kisom/cert && cd cert
  go build -o cert .
```

- Or install into your `$GOBIN`/`$GOPATH/bin`:

```
  go install github.com/kisom/cert@latest
```

- The releases page has binaries available.
