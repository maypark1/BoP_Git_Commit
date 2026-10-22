package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

// main runs experiments E1–E4 on one sample commit and prints signature/key sizes.
// Threat model M1: the attacker holds the Ed25519 secret key but not the ML-DSA one.
func main() {
	c := &Commit{
		Tree:    "a1b2c3",
		Parent:  "d4e5f6",
		Author:  "Chanmi Park",
		Message: "initial commit",
	}
	m := []byte(c.payload())

	pk, sk := ConcatKeyGen()
	sigH := ConcatSign(sk, m)            // honest composite signature
	sigF := ResignConcat(sk.Ed, sigH, m) // M1 key-compromise re-sign (salt fixed)

	fmt.Println("=== E1: ¬UNIQ (same content, two valid commit hashes) ===")
	fmt.Println("verify honest :", ConcatVerify(pk, m, sigH))
	fmt.Println("verify forged :", ConcatVerify(pk, m, sigF))
	hH := CommitHashWithSig(c, sigH.Bytes())
	hF := CommitHashWithSig(c, sigF.Bytes())
	fmt.Println("hash honest   :", hH)
	fmt.Println("hash forged   :", hF)
	fmt.Println("hashes differ :", hH != hF, " -> ¬UNIQ")
	fmt.Println()

	fmt.Println("=== E-recomb: v6 salt blocks component recombination (RFC 9980 §9.1) ===")
	sig1 := ConcatSign(sk, m)
	sig2 := ConcatSign(sk, m) // same message, different random salt
	recomb := RecombineConcat(sig1, sig2)
	fmt.Println("sig1 salt != sig2 salt :", !bytes.Equal(sig1.Salt, sig2.Salt))
	fmt.Println("recombined verify      :", ConcatVerify(pk, m, recomb), " -> rejected, salt defense holds")
	fmt.Println()

	fmt.Println("=== E2a: ¬OR-SUF — salt fixed, key-compromise re-sign (M1) ===")
	vH := ConcatVerify(pk, m, sigH)
	vF := ConcatVerify(pk, m, sigF)
	sameSalt := bytes.Equal(sigH.Salt, sigF.Salt)
	diff := !bytes.Equal(sigH.S1, sigF.S1)
	fmt.Println("same salt     :", sameSalt)
	fmt.Println("both valid    :", vH && vF)
	fmt.Println("sigs differ   :", diff, " -> strong forgery; salt did NOT help")
	fmt.Println()

	fmt.Println("=== E2b: OR-EUF preserved (no new-message forgery) ===")
	m2 := []byte("different message")
	sigF2 := ResignConcat(sk.Ed, sigH, m2) // reuses sigH.S2, which is over (salt‖algID‖m)
	fmt.Println("new-msg forge :", ConcatVerify(pk, m2, sigF2), " -> OR-EUF holds")
	fmt.Println()

	fmt.Println("=== E3: non-normalizable (forgery is canonical) ===")
	inForged := hashedInput(sigF.Salt, m) // check σ1′ alone with the stdlib verifier
	fmt.Println("std ed25519.Verify(forged):", ed25519.Verify(pk.Ed, inForged, sigF.S1))
	fmt.Println("forged sig length         :", len(sigF.S1), "bytes")
	fmt.Println()

	fmt.Println("=== E4: BoP-2 defense + size ===")
	bpk, bsk := BoPKeyGen()
	bs := BoPSign(bsk, m)
	fmt.Println("BoP honest verify  :", BoPVerify(bpk, m, bs))
	bsF := ResignBoP(bsk.a, bs) // same M1 attack: Schnorr secret only, σ2 reused
	fmt.Println("BoP re-sign verify :", BoPVerify(bpk, m, bsF), " -> rejected, OR-SUF restored")
	fmt.Println()

	fmt.Println("=== sizes (bytes, algorithm-level) ===")
	fmt.Println("ML-DSA only :", len(sigH.S2))
	fmt.Println("concat      :", len(sigH.S1)+len(sigH.S2), "(ed 64 + ML-DSA 2420)")
	fmt.Println("BoP-2       :", len(bs.Rsp.Bytes())+len(bs.S2), "(rsp 32 + ML-DSA 2420)")
	fmt.Println("note: v6 salt", saltLen, "B is added equally by the OpenPGP layer to both; omitted from comparison")

	// --- key sizes ---
	mlPubC, _ := pk.ML.MarshalBinary()
	mlPrivC, _ := sk.ML.MarshalBinary()
	bmlPub, _ := bpk.ML.MarshalBinary()
	bmlPriv, _ := bsk.ML.MarshalBinary()
	fmt.Println()
	fmt.Println("=== key sizes (bytes) ===")
	fmt.Println("concat pub :", len(pk.Ed)+len(mlPubC), "(ed", len(pk.Ed), "+ ML", len(mlPubC), ")")
	fmt.Println("concat priv:", len(sk.Ed)+len(mlPrivC), "(ed", len(sk.Ed), "+ ML", len(mlPrivC), ")")
	fmt.Println("BoP-2  pub :", len(bpk.A.Bytes())+len(bmlPub), "(A", len(bpk.A.Bytes()), "+ ML", len(bmlPub), ")")
	fmt.Println("BoP-2  priv:", len(bsk.a.Bytes())+len(bmlPriv), "(a", len(bsk.a.Bytes()), "+ ML", len(bmlPriv), ")")
}
