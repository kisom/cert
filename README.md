# cert - a certificate and x509 swiss army knife

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/kisom/cert/tree/master.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/kisom/cert/tree/master)

I've written a bunch of small programs in the 
[goutils](https://github.com/kisom/goutils/). I decided to consolidate them 
into one program I could hand other people. 

TODO: fill this out more once the initial import is done.

Embedding version information
-----------------------------

The `cert version` subcommand prints an embedded version string. This project
does not shell out to `git` at runtime. Instead, set the version at build time
using Go linker flags.

Examples:

- Local build with a specific version tag:

  go build -ldflags "-X cert/cmd.Version=v1.2.3" -o cert .

- Include a commit identifier:

  go build -ldflags "-X cert/cmd.Version=git-1b00701" -o cert .

- Installing with `go install` while setting the version:

  go install -ldflags "-X cert/cmd.Version=v1.2.3" ./...

If no value is provided, the default version string is "dev".