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

`cert` is a tool that combines a lot of the small programs I've
written over the last decade in building PKI systems. It's intended to
help test systems, diagnose errors, and generally assist with
validating PKI systems.

Most of the subcommands have documentation.

Requirements
------------

- Go toolchain installed. The module currently declares:
  - go 1.25 in `go.mod` (use a compatible or newer Go version).


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

- There is a homebrew tap available:

```
  brew tap kisom/homebrew-tap
  brew install cert
```

   This will also install the man pages and shell completions.
