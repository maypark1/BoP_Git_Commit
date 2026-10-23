package main

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func fixture() (*Commit, []byte) {
	c := &Commit{Tree: "a1b2c3", Parent: "d4e5f6", Author: "Researcher", Message: "same payload"}
	return c, []byte(c.payload())
}

func TestE1E2aSamePayloadSaltAndSecureComponent(t *testing.T) {
	c, m := fixture()
	pk, sk := ConcatKeyGen()
	honest := ConcatSign(sk, m)
	if !ConcatVerify(pk, m, honest) {
		t.Fatal("honest signature invalid")
	}
	forged := ResignConcat(sk.Ed, honest, m)
	if !bytes.Equal(honest.Salt, forged.Salt) {
		t.Fatal("salt changed")
	}
	if !bytes.Equal(honest.S2, forged.S2) {
		t.Fatal("uncompromised ML-DSA component changed")
	}
	if bytes.Equal(honest.S1, forged.S1) {
		t.Fatal("compromised Ed25519 signature unchanged")
	}
	if !ConcatVerify(pk, m, forged) {
		t.Fatal("re-signature invalid")
	}
	if bytes.Equal(honest.Bytes(), forged.Bytes()) {
		t.Fatal("signature bytes equal")
	}
	if CommitHashWithSig(c, honest.Bytes()) == CommitHashWithSig(c, forged.Bytes()) {
		t.Fatal("hashes equal")
	}
	if !bytes.Equal(m, []byte(c.payload())) {
		t.Fatal("payload changed")
	}
}

func TestE3AlternativeEd25519Signature(t *testing.T) {
	_, m := fixture()
	pk, sk := ConcatKeyGen()
	honest := ConcatSign(sk, m)
	forged := ResignConcat(sk.Ed, honest, m)
	input := hashedInput(honest.Salt, m)
	if !ed25519.Verify(pk.Ed, input, honest.S1) || !ed25519.Verify(pk.Ed, input, forged.S1) {
		t.Fatal("Ed25519 verification failed")
	}
	if bytes.Equal(honest.S1, forged.S1) {
		t.Fatal("distinct signatures expected")
	}
	// Repeating the standard deterministic API yields the original signature.
	if !bytes.Equal(ed25519.Sign(sk.Ed, input), honest.S1) {
		t.Fatal("standard Ed25519 unexpectedly nondeterministic")
	}
}

func TestE2bAndSaltRecombination(t *testing.T) {
	_, m := fixture()
	pk, sk := ConcatKeyGen()
	s1, s2 := ConcatSign(sk, m), ConcatSign(sk, m)
	if bytes.Equal(s1.Salt, s2.Salt) {
		t.Skip("random salts accidentally equal")
	}
	if ConcatVerify(pk, m, RecombineConcat(s1, s2)) {
		t.Fatal("different-salt recombination accepted")
	}
	changed := []byte("a distinct message")
	if ConcatVerify(pk, changed, ResignConcat(sk.Ed, s1, changed)) {
		t.Fatal("new-message attempt unexpectedly accepted")
	}
	// Rejection of one attempt is not a proof of UF-CMA.
}

func TestE4BoPCompromisedIDKey(t *testing.T) {
	_, m := fixture()
	pk, sk := BoPKeyGen()
	honest := BoPSign(sk, m)
	if !BoPVerify(pk, m, honest) {
		t.Fatal("honest BoP signature invalid")
	}
	for i := 0; i < 32; i++ {
		// Attacker has the real identification secret, not ML-DSA secret.
		candidate := ResignBoP(sk.a, honest)
		if !bytes.Equal(candidate.S2, honest.S2) {
			t.Fatal("attacker changed ML-DSA component")
		}
		if candidate.Rsp.Equal(honest.Rsp) == 1 {
			t.Fatal("new response unexpectedly equal")
		}
		if BoPVerify(pk, m, candidate) {
			t.Fatal("BoP accepted modified response with fixed ML-DSA signature")
		}
	}
	// This tests one explicit attack family; it does NOT establish SUF-CMA security.
}

func TestVerificationRejectsMalformed(t *testing.T) {
	c, m := fixture()
	_ = c
	cp, cs := ConcatKeyGen()
	if ConcatVerify(cp, m, nil) {
		t.Fatal("concat accepted nil")
	}
	s := ConcatSign(cs, m)
	s.S1 = s.S1[:10]
	if ConcatVerify(cp, m, s) {
		t.Fatal("concat accepted short signature")
	}
	bp, _ := BoPKeyGen()
	if BoPVerify(bp, m, nil) {
		t.Fatal("BoP accepted nil")
	}
}

// TestM2ConcatAndBoP exercises the ML-DSA-key-exposure case, complementary
// to the Ed25519/Schnorr-key-exposure tests above.
func TestM2ConcatAndBoP(t *testing.T) {
	c, m := fixture()
	pk, sk := ConcatKeyGen()
	honest := ConcatSign(sk, m)
	if !ConcatVerify(pk, m, honest) {
		t.Fatal("honest concat signature invalid")
	}
	modified := ResignConcatM2(sk.ML, honest, m)
	if !bytes.Equal(honest.Salt, modified.Salt) || !bytes.Equal(honest.S1, modified.S1) {
		t.Fatal("M2 must preserve salt and uncompromised Ed25519 signature")
	}
	if bytes.Equal(honest.S2, modified.S2) || !ConcatVerify(pk, m, modified) {
		t.Fatal("M2 must create a distinct valid ML-DSA signature")
	}
	if CommitHashWithSig(c, honest.Bytes()) == CommitHashWithSig(c, modified.Bytes()) {
		t.Fatal("M2 modeled commit hashes should differ")
	}
	bp, bs := BoPKeyGen()
	originalBoP := BoPSign(bs, m)
	if !BoPVerify(bp, m, originalBoP) {
		t.Fatal("honest BoP signature invalid")
	}
	candidate := ResignBoPM2(bs.ML, bp, originalBoP, m)
	if !bytes.Equal(originalBoP.Rsp.Bytes(), candidate.Rsp.Bytes()) {
		t.Fatal("M2 must preserve the identification response")
	}
	if bytes.Equal(originalBoP.S2, candidate.S2) || BoPVerify(bp, m, candidate) {
		t.Fatal("BoP-2 should reject the tested M2 substitution")
	}
}

// A short public key must produce false rather than a panic in ed25519.Verify.
func TestConcatRejectsMalformedPublicKey(t *testing.T) {
	_, m := fixture()
	pk, sk := ConcatKeyGen()
	sig := ConcatSign(sk, m)
	pk.Ed = pk.Ed[:10]
	if ConcatVerify(pk, m, sig) {
		t.Fatal("accepted malformed public key")
	}
}
