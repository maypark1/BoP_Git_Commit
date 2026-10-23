# When OR-SUF Matters — Reproducible Go Experiments

Research prototype accompanying **“When OR-SUF Matters: Hybrid Signature Combiners for Post-Quantum Git Commit Signing”** (Chanmi Park and Joohee Lee).

This repository compares a **concatenation-based hybrid signature** with a **Bird-of-Prey-2 (BoP-2)-inspired cross-binding construction**, using Ed25519, a Schnorr identification protocol over Edwards25519, and ML-DSA-44. The principal experiment is a **second valid signature on the same signed payload** after disclosure of exactly one component secret key.

## Research question and scope

A signed Git commit includes its signature bytes in the serialized object used to compute the commit identifier, although the signature bytes are excluded from the content that is signed. If an attacker can create a different valid signature for unchanged content, a different serialized object and therefore (except for a hash collision) a different identifier results.

The test harness uses a **simplified Git-like serializer** and SHA-256. It does **not** produce actual Git commits, OpenPGP packets, or a wire-compatible implementation of RFC 9980. The concatenation model uses a fixed illustrative algorithm identifier and a 16-byte salt; it should not be described as an implementation of the RFC 9980 standardized Ed25519 + ML-DSA-65 algorithm. The BoP-2 implementation is a research instantiation of the cyclic binding idea; security claims about the published construction must be attributed to Janneck's theorem and its assumptions, not inferred from these tests.

## Threat models

| Model | Exposed secret | Unexposed secret | Attempt |
| --- | --- | --- | --- |
| **M1** | Ed25519 key (concat) / Schnorr ID scalar (BoP-2) | ML-DSA-44 key | Create a new classical signature or response while retaining the original ML-DSA signature |
| **M2** | ML-DSA-44 key | Ed25519 key (concat) / Schnorr ID scalar (BoP-2) | Create a new ML-DSA signature while retaining the original classical signature or response |

The attacker knows the original payload, salt, public keys, and original valid hybrid signature. In M1 and M2 the **uncompromised component remains unchanged**. The experiment tests strong unforgeability-style *re-signing*, not the ability to sign a new payload.

## Repository map

| File | Purpose |
| --- | --- |
| `main.go` | Command-line demonstration of E1–E4 and both exposure models |
| `commit.go` | Simplified commit payload, signature embedding, SHA-256 object hash |
| `concat.go` | Hybrid concatenation keys, salt-bound signing, and verification |
| `attack.go` | Alternative-nonce Ed25519 signing; M1/M2 re-signing; salt recombination |
| `bop.go` | Schnorr/ML-DSA cross-binding, verification, M1/M2 substitutions |
| `research_test.go` | Behavioral assertions, including positive and negative checks |
| `time_bench_test.go` | Isolated signing and verification time benchmarks |
| `memory_bench_test.go` | Per-operation Go heap allocation benchmarks |
| `size_test.go` | Raw component-size assertions and output |
| `run_time.sh`, `run_memory.sh`, `run_size.sh` | Unix shell wrappers for the three measurement categories |
| `go.mod`, `go.sum` | Dependency versions and checksums |
| `LICENSE` | MIT license |

## Prerequisites

- Go toolchain compatible with the pinned dependencies (the original project declares **Go 1.27.2** in `go.mod`; use a toolchain that can satisfy this directive or adjust it only after checking library compatibility).
- Internet access on first build, unless dependencies are already in the Go module cache.
- `github.com/cloudflare/circl` v1.5.0 for ML-DSA-44.
- `filippo.io/edwards25519` v1.1.0 for point and scalar operations.

## Run the experiments

From the project directory:

```bash
go version
go mod download
go run .
go test -v -count=1 ./...
```

To repeat the BoP-2 M1 substitution test and run all benchmarks:

```bash
go test -run '^TestE4BoPCompromisedIDKey$' -count=10 -v
go test -run '^TestM2ConcatAndBoP$' -count=10 -v
go test -run '^$' -bench . -benchmem -count=5
```

**Expected qualitative observations** (the cryptographic randomness means the exact hashes/signatures vary):

| Experiment | Concatenation | BoP-2 / control |
| --- | --- | --- |
| **E1** same payload, different signature | Two signatures verify; modeled hashes differ | — |
| **E-recomb** mix components from different salts | Rejected | Salt-binding control |
| **E2a / M1** expose classical key, fix salt and ML-DSA signature | Modified signature verifies | Fresh response with fixed ML-DSA signature is rejected |
| **E2b** reuse the ML-DSA component on a new message | Rejected | This is one attempted forgery, not an EUF-CMA proof |
| **E3** canonical alternative Ed25519 signature | Standard `ed25519.Verify` accepts | Shows encoding normalization cannot distinguish this valid signature |
| **M2** expose ML-DSA key, fix salt and classical signature | Modified signature verifies | Changed ML-DSA signature with fixed response is rejected |

## Why the alternative Ed25519 signature is valid

Standard Ed25519 signing is **deterministic**. Calling `ed25519.Sign` again with the same private key and input produces the same signature. The M1 experiment therefore constructs an alternative signature using the exposed private scalar and a *fresh randomly selected nonce* via Edwards25519 group operations. It then verifies the result with Go's **standard Ed25519 verifier**. This is not a noncanonical encoding trick: the signature bytes are a different, valid 64-byte Ed25519 signature on the same input.

## How the BoP-2-inspired binding works

The classical identification commitment is `R = k·B`. ML-DSA signs a hash that binds the public keys, payload, and commitment: `m' = H1(A || pkML || m || R)`. The ML-DSA signature determines the Schnorr challenge `c = H2(sigML)`. The classical response is `z = k + c·a`. Verification recovers `R = z·B − c·A` and checks the ML-DSA signature against the reconstructed input. Consequently, replacing just `z` or just `sigML` normally changes the commitment/input reconstructed by the verifier.

`h1` and `h2` in the source are compact illustrative SHA-512-based encodings, **not a claim of bit-for-bit interoperability with Janneck's reference implementation**. For a deployable implementation, define unambiguous length-prefix encodings, explicit domain separation, error handling, and a full security review.

## Measured performance results (Windows/AMD64)

The following results were obtained by running the separate **time**, **memory**, and **size** experiments on an **AMD Ryzen 5 8645HS w/ Radeon 760M Graphics**, using Windows/AMD64 (`goos: windows`, `goarch: amd64`, `pkg: bop`). Each timing benchmark was run five times; values in the time table are **medians**. Go version and machine power settings were not captured in the supplied logs and should be recorded for future reproducibility.

### 1. Execution time

Run in PowerShell from the project root:

```powershell
go test -run '^$' -bench '^Benchmark(Concat|BoP)(Sign|Verify)$' -benchtime=1s -count=5
```

| Operation | Concatenation (median) | BoP-2 (median) | BoP-2 overhead |
| --- | ---: | ---: | ---: |
| Signing | **201.534 µs/op** | **212.326 µs/op** | **+5.36%** |
| Verification | **108.421 µs/op** | **120.776 µs/op** | **+11.40%** |

Raw time measurements (`ns/op`), in run order:

| Operation | Run 1 | Run 2 | Run 3 | Run 4 | Run 5 |
| --- | ---: | ---: | ---: | ---: | ---: |
| ConcatSign | 202693 | 199369 | 204970 | 201210 | 201534 |
| ConcatVerify | 108421 | 107012 | 160809 | 112369 | 108097 |
| BoPSign | 209434 | 208453 | 212326 | 216966 | 213098 |
| BoPVerify | 120776 | 125629 | 120247 | 123167 | 116755 |

`ns/op` is nanoseconds per operation; divide by 1,000 to obtain `µs/op`. The high third ConcatVerify sample (160,809 ns/op) remains in the raw data and is not silently discarded; the median limits its influence.

### 2. Memory allocation

```powershell
go test -run '^$' -bench '^BenchmarkMemory(Concat|BoP)(Sign|Verify)$' -benchmem -benchtime=1s -count=5
```

| Operation | Concatenation (B/op) | BoP-2 (B/op) | Concat (allocs/op) | BoP-2 (allocs/op) |
| --- | ---: | ---: | ---: | ---: |
| Signing | **3,426** | **9,474** | **10** | **10** |
| Verification | **578** | **546** | **6** | **5** |

All five samples for each operation reported identical allocation metrics. BoP-2 allocated **6,048 additional bytes per signing operation** (+176.53%), while allocating **32 fewer bytes per verification** (−5.54%). `B/op` is cumulative Go heap bytes allocated per operation, **not** peak resident set size (RSS), live heap size, or total process memory. The timing columns printed during `-benchmem` are not substituted for the independently measured timing results above.

### 3. Signature size

```powershell
go test -run '^TestSignatureSizes$' -v -count=1
```

Observed test output:

```text
scheme,component1_bytes,mldsa44_bytes,raw_signature_bytes,salt_bytes
concat,64,2420,2484,16
bop2,32,2420,2452,0
--- PASS: TestSignatureSizes (0.01s)
PASS
```

| Construction | Component 1 | ML-DSA-44 | Raw signature size | Separate salt |
| --- | ---: | ---: | ---: | ---: |
| Concatenation | Ed25519: 64 B | 2,420 B | **2,484 B** | 16 B |
| BoP-2-inspired | Schnorr response: 32 B | 2,420 B | **2,452 B** | 0 B |

BoP-2's **raw signature components are 32 B smaller (1.29%)**. This is a comparison of **raw cryptographic signature components only**. If the 16-byte salt is counted, the concatenation demo carries 2,500 B of signature-plus-salt data. Neither size includes Git object serialization, OpenPGP framing, or key material. The schemes do not use identical framing, so the 32-byte figure must not be presented as a full serialized-commit size reduction.

### Reproducing and saving results

First run `go mod download` and `go test ./...`. On Windows PowerShell, capture each category independently:

```powershell
go test -run '^$' -bench '^Benchmark(Concat|BoP)(Sign|Verify)$' -benchtime=1s -count=5 | Tee-Object time_results.txt
go test -run '^$' -bench '^BenchmarkMemory(Concat|BoP)(Sign|Verify)$' -benchmem -benchtime=1s -count=5 | Tee-Object memory_results.txt
go test -run '^TestSignatureSizes$' -v -count=1 | Tee-Object size_results.txt
```

On a Unix-like shell, the included `run_time.sh`, `run_memory.sh`, and `run_size.sh` scripts perform these tasks. Record `go version`, `go env GOOS GOARCH`, CPU model, and power configuration alongside the output. All values in this section come from the supplied Windows benchmark logs, not from a fresh run on another host.

## Interpretation and limitations

- A second valid signature on an already-signed payload witnesses the failure of the modeled one-key-exposure strong-unforgeability goal for concatenation.
- Distinct modeled commit identifiers follow from distinct serialized bytes, except for the negligible possibility of a SHA-256 collision.
- A rejected *particular* BoP-2 substitution is an empirical result; it is **not a proof** of OR-SUF-CMA or of every possible attack being blocked.
- The experiment does not implement Git's actual `gpgsig` header folding, full commit metadata, OpenPGP v6 signature packets, or standardized RFC 9980 parameter selection.
- Randomized ML-DSA signing is requested explicitly for M2 to obtain a distinct valid signature while preserving the salt and classical component.

## References

1. RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
2. NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA).
3. RFC 9980 — OpenPGP hybrid post-quantum signatures (compare standardized algorithm identifiers and parameter sets before deployment).
4. Janneck, *Bird of Prey: Practical Signature Combiners Preserving Strong Unforgeability*, EUROCRYPT 2026 / ePrint 2025/1844, especially Theorem 6.
5. Ginesin, *Git Hash Chain Malleability*, arXiv:2607.02820.

## License

MIT. See `LICENSE`.


## Separate performance measurements

The experiments are separated into three independent categories. Run all
commands from the repository root after `go test ./...` succeeds.

### Execution time

```bash
bash run_time.sh
```

Source: `time_bench_test.go`. Output: `time_results.txt`.
Read `ns/op` for concatenation and BoP-2 signing and verification separately.
Convert to microseconds with `us/op = ns/op / 1000`. Report the median of
five benchmark samples. Key generation and verification fixtures are outside
the measured loop. Benchmark timings depend on CPU and Go version.

### Memory allocations

```bash
bash run_memory.sh
```

Source: `memory_bench_test.go`. Output: `memory_results.txt`.
Read `B/op` (heap bytes allocated per operation) and `allocs/op` (heap
allocations per operation). These metrics are **not peak process memory or
RSS**. Key generation and verification fixtures are excluded from the loop.

### Signature size

```bash
bash run_size.sh
```

Source: `size_test.go`. Output: `size_results.txt`.
The test prints CSV-compatible data. Concatenation is 64-byte Ed25519 plus
2,420-byte ML-DSA-44 = **2,484 bytes**; BoP-2 is a 32-byte Schnorr response
plus 2,420-byte ML-DSA-44 = **2,452 bytes**. Both numbers exclude salt,
Git/OpenPGP framing, and message length. `ConcatSig.Bytes()` includes an
additional 16-byte salt, making its demo serialization 2,500 bytes; this
is different from the paper's raw-signature-size metric.

### Reproducibility

Record `go version`, `go env GOOS GOARCH`, CPU model, power settings,
dependency versions (`go list -m all`), and all five benchmark samples.
Do not present historical paper measurements as measurements reproduced
on a different machine.
