#!/usr/bin/env bash
set -euo pipefail
go test -run '^TestSignatureSizes$' -v -count=1 | tee size_results.txt
