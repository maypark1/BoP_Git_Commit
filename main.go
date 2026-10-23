package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

func main() {
	c := &Commit{Tree: "a1b2c3", Parent: "d4e5f6", Author: "Researcher", Message: "same payload"}
	m := []byte(c.payload())
	pk, sk := ConcatKeyGen()
	honest := ConcatSign(sk, m)
	modified := ResignConcat(sk.Ed, honest, m)
	fmt.Println("ML-DSA mode: hedged (randomized); targeted component-substitution experiments")
	fmt.Println("MODEL: ML-DSA-44 + Ed25519; NOT a complete RFC 9980 OpenPGP implementation")
	fmt.Println("E1/E2a honest verifies:", ConcatVerify(pk, m, honest))
	fmt.Println("E1/E2a modified verifies:", ConcatVerify(pk, m, modified))
	fmt.Println("E2a unchanged salt:", bytes.Equal(honest.Salt, modified.Salt))
	fmt.Println("E2a unchanged ML-DSA signature:", bytes.Equal(honest.S2, modified.S2))
	fmt.Println("E2a changed Ed25519 signature:", !bytes.Equal(honest.S1, modified.S1))
	fmt.Println("E1 distinct modeled Git hashes:", CommitHashWithSig(c, honest.Bytes()) != CommitHashWithSig(c, modified.Bytes()))
	fmt.Println("E3 standard Ed25519 verifier accepts modified:", ed25519.Verify(pk.Ed, hashedInput(honest.Salt, m), modified.S1))
	other := []byte("different payload")
	fmt.Println("E2b one new-message attempt accepted:", ConcatVerify(pk, other, ResignConcat(sk.Ed, honest, other)))
	bp, bs := BoPKeyGen()
	bHonest := BoPSign(bs, m)
	bAttack := ResignBoP(bs.a, bHonest)
	fmt.Println("E4 honest BoP verifies:", BoPVerify(bp, m, bHonest))
	fmt.Println("E4 ID-secret-key attack with fixed ML-DSA accepted:", BoPVerify(bp, m, bAttack))
	fmt.Println("E4 unchanged ML-DSA signature:", bytes.Equal(bHonest.S2, bAttack.S2))
	fmt.Println("sizes excluding salt: concat", len(honest.S1)+len(honest.S2), "B, BoP", len(bHonest.Rsp.Bytes())+len(bHonest.S2), "B")
	// M2: keep the classical signature and salt, re-sign only ML-DSA.
	m2 := ResignConcatM2(sk.ML, honest, m)
	fmt.Println("M2 concat salt unchanged:", bytes.Equal(honest.Salt, m2.Salt))
	fmt.Println("M2 concat Ed25519 unchanged:", bytes.Equal(honest.S1, m2.S1))
	fmt.Println("M2 concat ML-DSA changed:", !bytes.Equal(honest.S2, m2.S2))
	fmt.Println("M2 concat modified verifies:", ConcatVerify(pk, m, m2))
	fmt.Println("M2 modeled commit hashes differ:", CommitHashWithSig(c, honest.Bytes()) != CommitHashWithSig(c, m2.Bytes()))
	bM2 := ResignBoPM2(bs.ML, bp, bHonest, m)
	fmt.Println("M2 BoP-2 ML-DSA changed:", !bytes.Equal(bHonest.S2, bM2.S2))
	fmt.Println("M2 BoP-2 substituted signature verifies:", BoPVerify(bp, m, bM2))
	fmt.Println("NOTE: Targeted attack tests do not constitute a formal OR-SUF proof.")
}
