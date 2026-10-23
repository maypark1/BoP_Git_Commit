# BoP Git Commit

Research proof of concept comparing **Ed25519 + ML-DSA-44 concatenation** with a **Schnorr-type / ML-DSA-44 BoP-2 construction** for signature-inclusive Git commit identifiers.

The model places signature bytes inside the hashed commit object and outside the signed payload. The experiments keep the payload fixed and compare component substitution under concatenation and cyclic cross-binding.

## Scope and construction

- The commit serializer is a simplified research model, not a complete Git/OpenPGP integration.
- Concatenation signs `salt || experimental domain tag || payload` with both components. A fresh 16-byte salt is generated for each honest signature and retained during substitution.
- BoP-2 uses a Schnorr-type identification component on edwards25519 and ML-DSA-44. It transmits a 32-byte response and the ML-DSA signature; the verifier reconstructs the commitment.
- H1 and H2 use separate experimental domain labels. These labels are not assigned OpenPGP algorithm identifiers.
- All ML-DSA signing uses CIRCL's **hedged mode** (`randomized=true`, empty context).
- ML-DSA-44 is used for the PoC. RFC 9980 instead specifies ML-DSA-65 + Ed25519 and ML-DSA-87 + Ed448.

The OR-preservation analysis follows the assumptions and results of the cited combiner literature. M1/M2 below are targeted substitutions implemented with one component secret; they illustrate cross-binding behavior rather than define a separate security game or establish general OR-SUF-CMA security.

## Requirements

- Go 1.23 or later
- `filippo.io/edwards25519 v1.1.0`
- `github.com/cloudflare/circl v1.5.0`
- Dependencies are pinned in `go.mod` and `go.sum`.

## Run

From the project directory:

```sh
go test -count=1 -v ./...
go run .
```

Full experiments on Unix:

```sh
sh run_experiments.sh
```

Windows PowerShell:

```powershell
.\run_experiments.ps1
```

If the downloaded script is blocked because it is unsigned, permit it for the current PowerShell session and rerun:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\run_experiments.ps1
```

The process-scoped setting ends when that PowerShell session closes.

The scripts save `environment.txt`, `correctness.txt`, `demo.txt`, `time_results.txt`, `memory_results.txt`, and `size_results.txt` under `results/`. Existing files at those paths are overwritten on rerun; preserve a run's files together before collecting another run.

## Correctness experiments

| Experiment | Conditions | Observed result |
|---|---|---|
| Honest signatures | Original payload and keys | Both constructions verify |
| M1 concatenation | Alternative Ed25519 nonce; original salt and ML-DSA signature | Distinct signature verifies; modeled commit hash changes |
| Ed25519 verifier check | Original and alternative signatures on the same input | Both accepted by Go `crypto/ed25519.Verify` |
| Cross-salt recombination | Components from two honest signatures with different salts | Rejected |
| New-message attempt | Re-sign Ed25519 for another payload, retaining original ML-DSA signature | Rejected |
| M1 BoP-2 | Modify response using the ID secret; retain ML-DSA signature | Tested substitutions rejected |
| M2 concatenation | Re-sign ML-DSA; retain salt and Ed25519 signature | Distinct signature verifies; modeled commit hash changes |
| M2 BoP-2 | Re-sign ML-DSA over the reconstructed commitment; retain response | Tested substitution rejected |
| Malformed inputs | Nil/short signatures and malformed Ed25519 public-key length | Rejected |

M1 generates a signature with a fresh nonce using low-level curve operations. It does not change the deterministic behavior of the standard Ed25519 signing API. The test also checks that repeating `ed25519.Sign` on the same input returns the original signature.

All eight tests are marked PASS in `results/correctness.txt` (the latest run used Go's test cache). The independently executed demo confirms the M1/M2 outcomes above. Use `go test -count=1 -v ./...` to force a fresh test run.

## Benchmark results

Environment recorded in `results/environment.txt`:

| Item | Value |
|---|---|
| CPU | AMD Ryzen 5 8645HS with Radeon 760M Graphics |
| OS / architecture | Windows / AMD64 |
| Go | 1.27.2 |
| ML-DSA mode | Hedged (randomized) |
| Timing method | Five benchmark samples per operation, `-benchtime=1s`; median reported |

The benchmark payload is the fixed byte string defined as `benchM` in `time_bench_test.go`. Timing and allocation runs are separate. Source logs are committed under `results/`. All samples are retained, including slower samples; figures below use the latest complete timing log rather than the earlier partial run. CPU power mode was not recorded. Run-to-run timing variation is visible in the samples, so overhead percentages describe this measurement set.

### Time

Median time in **microseconds per operation**:

| Scheme | Key generation | Signing | Verification |
|---|---:|---:|---:|
| ML-DSA-44 | 81.689 | 184.702 | 24.147 |
| Ed25519 | 33.059 | 41.530 | 91.748 |
| Concatenation | 121.174 | 211.219 | 116.535 |
| BoP-2 | 116.331 | 239.520 | 145.894 |

Relative to concatenation, BoP-2 signing takes **13.40%** more time and verification takes **25.19%** more time in this run. Each percentage is computed from the corresponding medians: `(BoP / concat - 1) * 100`.

### Raw signature size

| Scheme | Classical component / response | ML-DSA-44 | Raw signature total | Modeled salt |
|---|---:|---:|---:|---:|
| Concatenation | 64 B | 2420 B | 2484 B | 16 B |
| BoP-2 | 32 B | 2420 B | 2452 B | 0 B |

BoP-2 reduces raw component size by **32 bytes**. Salt and OpenPGP packet/armor overhead are excluded from the raw total. Library-internal private-key encodings are not RFC packet sizes.

### Heap allocation

Median allocated bytes and allocation counts per operation:

| Scheme | Signing B/op | Signing allocs/op | Verification B/op | Verification allocs/op |
|---|---:|---:|---:|---:|
| Concatenation | 3,506 | 10 | 658 | 6 |
| BoP-2 | 9,538 | 11 | 610 | 6 |

`B/op` measures Go heap bytes allocated per operation; it is not peak memory, resident memory, or total working memory. Timing figures come from the dedicated time run, not the allocation run.

### Retained timing samples

All five samples below are **ns/op**. Divide by 1000 for microseconds.

| Benchmark | Sample 1 | Sample 2 | Sample 3 | Sample 4 | Sample 5 |
|---|---:|---:|---:|---:|---:|
| MLDSASign | 165561 | 162301 | 208381 | 245571 | 184702 |
| MLDSAVerify | 23567 | 23508 | 24214 | 24840 | 24147 |
| ConcatSign | 201262 | 211219 | 205460 | 214863 | 222510 |
| ConcatVerify | 116959 | 111306 | 116535 | 116313 | 119789 |
| BoPSign | 240185 | 221254 | 239199 | 249641 | 239520 |
| BoPVerify | 134547 | 147117 | 128409 | 147002 | 145894 |
| Ed25519Sign | 40030 | 54041 | 47116 | 39504 | 41530 |
| Ed25519Verify | 91399 | 88578 | 92082 | 92932 | 91748 |
| MLDSAKeyGen | 88546 | 75203 | 79162 | 81689 | 82319 |
| Ed25519KeyGen | 33059 | 31972 | 33250 | 34305 | 31709 |
| ConcatKeyGen | 121174 | 116686 | 113463 | 123269 | 178391 |
| BoPKeyGen | 126260 | 108377 | 116331 | 120534 | 113564 |

## Files

| File | Purpose |
|---|---|
| `concat.go` | Concatenation with experimental domain tag and v6-style salt |
| `bop.go` | Cyclic cross-binding and targeted BoP substitutions |
| `attack.go` | Alternative-nonce Ed25519 and ML-DSA substitutions |
| `commit.go` | Simplified signature-inclusive commit hashing |
| `research_test.go` | Correctness and substitution tests |
| `time_bench_test.go` | Timing benchmarks |
| `memory_bench_test.go` | Heap-allocation benchmarks |
| `size_test.go` | Raw component-size checks |
| `run_experiments.ps1` / `.sh` | Full experiment collection |

## References

- Jonas Janneck. *Bird of Prey: Practical Signature Combiners Preserving Strong Unforgeability*. EUROCRYPT 2026; Cryptology ePrint Archive 2025/1844. https://eprint.iacr.org/2025/1844
- RFC 8032. *Edwards-Curve Digital Signature Algorithm (EdDSA)*. https://www.rfc-editor.org/rfc/rfc8032
- NIST FIPS 204. *Module-Lattice-Based Digital Signature Standard* (2024).
- RFC 9980. *Post-Quantum Cryptography in OpenPGP* (2026). https://www.rfc-editor.org/rfc/rfc9980

See `LICENSE` for license terms.
