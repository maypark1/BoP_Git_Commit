#!/bin/sh
set -eu
mkdir -p results
{ go version; go env GOOS GOARCH; uname -a; } > results/environment.txt
go test -count=1 -v ./... > results/correctness.txt 2>&1
cat results/correctness.txt
go run . > results/demo.txt
go test -run '^$' -bench '^Benchmark(MLDSA|Ed25519|Concat|BoP)(KeyGen|Sign|Verify)$' -benchtime=1s -count=5 > results/time_results.txt
go test -run '^$' -bench '^BenchmarkMemory(Concat|BoP)(Sign|Verify)$' -benchmem -benchtime=1s -count=5 > results/memory_results.txt
go test -run '^TestSignatureSizes$' -v > results/size_results.txt
