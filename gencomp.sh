#!/usr/bin/env bash

compdir="completions"

set -e

if [ -e $compdir ]
then
    rm -r $compdir
fi

mkdir completions

for sh in bash zsh fish; do
	go run main.go completion "$sh" >"$compdir/cert.$sh"
done
