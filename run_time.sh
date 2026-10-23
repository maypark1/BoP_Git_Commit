#!/usr/bin/env bash
set -euo pipefail
go test -run '^$' -bench '^Benchmark(Concat|BoP)(Sign|Verify)$' -benchtime=1s -count=5 | tee time_results.txt
