#!/usr/bin/env bash
set -euo pipefail
go test -run '^$' -bench '^BenchmarkMemory(Concat|BoP)(Sign|Verify)$' -benchmem -benchtime=1s -count=5 | tee memory_results.txt
