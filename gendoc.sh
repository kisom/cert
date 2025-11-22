#!/usr/bin/env bash

go run main.go docgen -o docs

./gencomp.sh

mkdir -p docs/man5
scdoc < bundle.5.scd  > docs/man5/cert-bundler.5
scdoc < request.5.scd > docs/man5/cert-request.5
