# When OR-SUF Matters — Proof of Concept

Proof-of-concept for the paper **"When OR-SUF Matters: Hybrid Signature
Combiners for Post-Quantum Git Commit Signing"** (MobiSec 2026).

Git commit signing is moving to hybrid post-quantum signatures (EdDSA + ML-DSA),
standardized in RFC 9980 as a plain **concatenation** with no cross-binding. This
repository demonstrates that the concatenation **fails to provide OR-SUF** (strong
unforgeability under single-component key compromise) and that the **Bird-of-Prey
(BoP-2)** combiner restores it.

## What it shows

- **Attack (key-compromise re-signing).** With one component key compromised and
  the v6 salt held fixed, re-signing only that component yields a *second valid
  signature on the same commit* — two valid commit hashes for identical content
  (¬OR-SUF). The forgery is a canonical Ed25519 signature, so no verifier-side
  normalization can remove it.
- **Defense (BoP-2).** A cyclic cross-binding combiner in which re-signing one
  component requires **both** secret keys. It rejects the attack and restores
  OR-SUF, with a composite signature 32 B smaller than the concatenation.

## Experiments

| Exp. | Result |
|------|--------|
| E1       | ¬UNIQ: two valid hashes, same content |
| E-recomb | cross different-salt components → rejected (§9.1 salt defense holds) |
| E2a      | salt fixed, re-sign Ed25519 → ¬OR-SUF |
| E2b      | new-message forge → fails → OR-EUF preserved |
| E3       | forgery passes standard Ed25519 verification, 64 B canonical |
| E4       | BoP-2 re-signing rejected → OR-SUF restored |

Core contrast: **E-recomb (rejected) vs E2a (succeeds)** — the v6 salt stops
keyless remixing but not key-compromise re-signing.

## Build & run

Requires **Go 1.27.2** (or newer).

```bash
go run .                        # run experiments E1–E4
go test -bench . -benchmem      # size / time / memory benchmarks
```

## Results

Measured on an **AMD Ryzen 5 8645HS**, Go 1.27.2, `cloudflare/circl` v1.5.0,
median of 5 runs. Commit hashing uses SHA-256; signatures use RFC 9980 v6 salts.

**Size (bytes)** — BoP-2 is 32 B smaller in signature and secret key.

| Scheme | Sig | pk | sk |
|--------|-----|----|----|
| ML-DSA-44 | 2420 | 1312 | 2560 |
| concat    | 2484 | 1344 | 2624 |
| **BoP-2** | **2452** | 1344 | **2592** |

**Time (µs)** — sign +12%, verify +16% vs. concatenation; key generation ≈ equal.

| Scheme | KeyGen | Sign | Verify |
|--------|--------|------|--------|
| ML-DSA-44 | 71 | 140 | 23 |
| concat    | 97 | 198 | 109 |
| **BoP-2** | 94 | 221 | 126 |

Forgery cost (ReSign) ≈ **40 µs** — about 5× cheaper than an honest signature
(198 µs), since σ₂ is reused.

## Dependencies

- [`github.com/cloudflare/circl`](https://github.com/cloudflare/circl) v1.5.0 — ML-DSA-44 (`sign/mldsa/mldsa44`)
- [`filippo.io/edwards25519`](https://filippo.io/edwards25519) — Ed25519 group operations

## Citation

> C. Park and J. Lee. *When OR-SUF Matters: Hybrid Signature Combiners for
> Post-Quantum Git Commit Signing.* MobiSec 2026.

## Authors

- **Chanmi Park** — Sungshin Women's University — parkchanmi801@gmail.com
- **Joohee Lee** (corresponding author)

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
