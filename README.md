# cert — a certificate and X.509 swiss‑army knife

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/kisom/cert/tree/master.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/kisom/cert/tree/master)

cert is a small command‑line tool for inspecting and working with X.509/TLS
certificates and connections. It consolidates several utilities from
[goutils](https://github.com/kisom/goutils/) into a single, ergonomic CLI.


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

Option A: From source (local clone)

- Build a local binary:

```
  git clone https://github.com/kisom/cert && cd cert
  go build -o cert .
```

- Or install into your `$GOBIN`/`$GOPATH/bin`:

```
  go install github.com/kisom/cert@latest
```

- 

Option B: With an embedded version string

See the "Embedding version information" section below for `-ldflags` usage.

Option C: From releases

- This project is configured for GoReleaser. Prebuilt archives may be published
  on GitHub under `kisom/cert` when releases are cut. If a release is missing
  for your platform, build from source.  
  TODO: Link directly to the Releases page once available.


Usage
-----

Each subcommand has `--help`. Global flags apply to all commands.

Global flags (from `cmd/config.go`):

- --config string                  Path to config file (default: $HOME/.config/goutils/cert.yaml)
- -c, --ca-file string            CA certificate bundle file (PEM)
- -d, --display-mode string       Hex display mode for SKI (lower|upper) (default: lower)
- -i, --intermediates-file string Intermediate certificate bundle (PEM)
- -k, --skip-verify               Skip certificate verification
- -t, --strict-tls                Use strict TLS settings
- -v, --verbose                   Verbose output

Subcommands:

- cert tlsinfo <host:port> [more ...]
  Connect and print TLS connection details (TLS version, cipher suite, and
  peer cert subjects/issuers). Uses a proxy‑aware dialer and does not validate
  the peer (InsecureSkipVerify=true) — intended for inspection.

- cert dump [host:port|cert.pem]...
  Fetch and display certificates for a host or dump one or more certificate
  files. With `--leaf-only`, print only the leaf when connecting to a host.
  Local flag: `-l, --leaf-only`.

- cert stealchain <host:port> [more ...]
  Retrieve and save the presented certificate chain from one or more TLS
  endpoints to `<host>.pem` files. Honors `--ca-file`; uses system pool if not
  provided. Local flag: `-s, --sni-name` to override SNI.

- cert matchkey -c cert.pem -k key.pem
  Check whether the given certificate and private key correspond. Returns
  non‑zero on mismatch unless `--verbose` is set and a match is found.
  Local flag: `-k, --key-file`.

- cert ski <key-or-cert> [more ...]
  Display the Subject Key Identifier (SKI) for one or more keys/certs. With
  `--should-match`, compares all SKIs and warns on mismatch. Honors
  `--display-mode` for hex formatting. Local flag: `-m, --should-match`.

- cert verify <host:port|cert.pem> [more ...]
  Verify certificate chains for hosts or cert files. Supports custom root and
  intermediate bundles, optional forced intermediate loading, optional
  revocation checks, and verbose progress.
  Local flags: `-f, --force-intermediate-bundle`, `-r, --check-revocation`.

- cert version
  Print the embedded version string.


Configuration and Environment
-----------------------------

Configuration is managed via Cobra flags and Viper. Behavior is influenced by:

- Flags listed above.
- Environment variables: Viper's `AutomaticEnv()` is enabled, so any of the
  flag names may be provided as environment variables (uppercase, with dashes
  typically replaced by underscores by the shell when exporting). Examples:
  - CA_FILE, INTERMEDIATES_FILE, DISPLAY_MODE, SKIP_VERIFY, STRICT_TLS, VERBOSE,
    LEAF_ONLY, SHOULD_MATCH, SNI_NAME, FORCE_INTERMEDIATE_BUNDLE, CHECK_REVOCATION
  Note: Viper's default behavior is case‑insensitive lookup; exact mapping may
  depend on your environment.
- Config file: by default, `$HOME/.config/goutils/cert.yaml` if present. You can
  set a custom file via `--config <path>`.

Example config (`~/.config/goutils/cert.yaml`):

  ca-file: /etc/ssl/certs/ca-bundle.crt
  intermediates-file: /path/to/intermediates.pem
  display-mode: lower
  skip-verify: false
  strict-tls: true
  verbose: false
  should-match: false
  leaf-only: false
  sni-name: ""
  force-intermediate-bundle: false
  check-revocation: false


Embedding version information
-----------------------------

The `cert version` subcommand prints an embedded version string. The version
information is set at build time using Go linker flags.

Examples:

- Local build with a specific version tag:

```
  go build -ldflags "-X cert/cmd.Version=v1.2.3" -o cert .
```

- Include a commit identifier:
- 
```
  go build -ldflags "-X cert/cmd.Version=git-1b00701" -o cert .
```

- Installing with `go install` while setting the version:
- 
```
  go install -ldflags "-X cert/cmd.Version=v1.2.3" ./...
```

If no value is provided, the default version string is "dev".


Project Structure
-----------------

Top‑level files and directories:

- `main.go` — entry point, calls `cmd.Execute()`.
- `cmd/` — Cobra command implementations:
  - `root.go` — root command and CLI description.
  - `config.go` — global flags, Viper config/env setup, TLS helpers.
  - `dump.go` — `cert dump`.
  - `matchkey.go` — `cert matchkey`.
  - `ski.go` — `cert ski`.
  - `stealchain.go` — `cert stealchain`.
  - `tlsinfo.go` — `cert tlsinfo`.
  - `verify.go` — `cert verify`.
  - `version.go` — `cert version`.
- `tlsinfo/` — small helper package for printing TLS connection details.
- `.goreleaser.yaml` — GoReleaser configuration.
- `.circleci/` — CircleCI pipeline configuration.
- `LICENSE` — Apache 2.0 license.


License
-------

This project is licensed under the Apache License, Version 2.0. See the
`LICENSE` file for details.


Notes
-----

- Module path is `cert`. When importing within this repository, packages are
  referenced as `cert/...` (e.g., `cert/cmd`, `cert/tlsinfo`). If you fork and
  change the module path, update imports accordingly.
- Proxy‑aware networking and TLS helpers come from
  `git.wntrmute.dev/kyle/goutils`.


[spf13/cobra]: https://github.com/spf13/cobra
[spf13/viper]: https://github.com/spf13/viper
[goreleaser]: https://goreleaser.com