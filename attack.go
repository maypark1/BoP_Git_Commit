package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// re-sign with a FRESH random nonce (standard ed25519 is deterministic → identical sig);
// low-level edwards25519 lets us pick a new nonce so σ1′ ≠ σ1 while both stay valid.
func resignEd25519(edPriv ed25519.PrivateKey, msg []byte) []byte {
	seed := edPriv.Seed()
	h := sha512.Sum512(seed)
	a, _ := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	A := edPriv.Public().(ed25519.PublicKey)

	randBytes := make([]byte, 64)
	rand.Read(randBytes)
	r, _ := edwards25519.NewScalar().SetUniformBytes(randBytes)
	R := new(edwards25519.Point).ScalarBaseMult(r)

	hram := sha512.New()
	hram.Write(R.Bytes())
	hram.Write(A)
	hram.Write(msg)
	k, _ := edwards25519.NewScalar().SetUniformBytes(hram.Sum(nil))

	S := edwards25519.NewScalar().MultiplyAdd(k, a, r)
	sig := make([]byte, 64)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())
	return sig
}

// M1 key-compromise re-signing: keep the SAME salt, re-sign the Ed component with the
// compromised key, reuse the untouched ML component. The v6 salt does not prevent this.
func ResignConcat(edPriv ed25519.PrivateKey, orig *ConcatSig, m []byte) *ConcatSig {
	in := hashedInput(orig.Salt, m)
	return &ConcatSig{
		Salt: orig.Salt,
		S1:   resignEd25519(edPriv, in),
		S2:   orig.S2,
	}
}

// Recombination (the attack RFC 9980 §9.1 claims to prevent): take the Ed component from
// one composite signature and the ML component from another. Different salts ⇒ it fails.
func RecombineConcat(sig1, sig2 *ConcatSig) *ConcatSig {
	return &ConcatSig{
		Salt: sig1.Salt,
		S1:   sig1.S1,
		S2:   sig2.S2,
	}
}
