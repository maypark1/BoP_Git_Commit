package main

import (
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// BoP-2 combiner: a Schnorr component on edwards25519 cyclically bound to ML-DSA-44.
// ML-DSA signs a digest that includes the Schnorr commitment R, and the Schnorr
// challenge is derived from the ML-DSA signature, so neither component can be
// replaced without the other's secret key.

type BoPPub struct {
	A  *edwards25519.Point // Schnorr public key A = a·B
	ML *mldsa44.PublicKey
}
type BoPPriv struct {
	a  *edwards25519.Scalar // Schnorr secret scalar
	A  *edwards25519.Point
	ML *mldsa44.PrivateKey
}
type BoPSig struct {
	Rsp *edwards25519.Scalar // Schnorr response rsp = c·a + k (32 B); R is not sent
	S2  []byte               // ML-DSA-44 signature over h1(A, pk_ml, m, R)
}

// randScalar returns a uniformly random scalar mod ℓ.
func randScalar() *edwards25519.Scalar {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	s, _ := edwards25519.NewScalar().SetUniformBytes(b)
	return s
}

func BoPKeyGen() (*BoPPub, *BoPPriv) {
	a := randScalar()
	A := new(edwards25519.Point).ScalarBaseMult(a)
	mlPub, mlPriv, _ := mldsa44.GenerateKey(rand.Reader)
	return &BoPPub{A, mlPub}, &BoPPriv{a, A, mlPriv}
}

// h1 is the message ML-DSA signs: SHA-512(A ‖ pk_ml ‖ m ‖ R).
// Binding R here ties σ2 to one specific Schnorr nonce.
func h1(A *edwards25519.Point, mlPub *mldsa44.PublicKey, m []byte, R *edwards25519.Point) []byte {
	pk2, _ := mlPub.MarshalBinary()
	h := sha512.New()
	h.Write(A.Bytes())
	h.Write(pk2)
	h.Write(m)
	h.Write(R.Bytes())
	return h.Sum(nil)
}

// h2 derives the Schnorr challenge from the ML-DSA signature: c = SHA-512(σ2) mod ℓ.
func h2(sig2 []byte) *edwards25519.Scalar {
	d := sha512.Sum512(sig2)
	c, _ := edwards25519.NewScalar().SetUniformBytes(d[:])
	return c
}

// BoPSign: R = k·B, σ2 = ML-DSA.Sign(h1(A, pk_ml, m, R)), c = h2(σ2), rsp = c·a + k.
func BoPSign(sk *BoPPriv, m []byte) *BoPSig {
	k := randScalar()
	R := new(edwards25519.Point).ScalarBaseMult(k)
	mlPub := sk.ML.Public().(*mldsa44.PublicKey)
	mp := h1(sk.A, mlPub, m, R)
	s2 := make([]byte, mldsa44.SignatureSize)
	mldsa44.SignTo(sk.ML, mp, nil, false, s2)
	chl := h2(s2)
	rsp := edwards25519.NewScalar().MultiplyAdd(chl, sk.a, k)
	return &BoPSig{Rsp: rsp, S2: s2}
}

// BoPVerify recomputes R = rsp·B − c·A and accepts iff σ2 verifies on h1(A, pk_ml, m, R).
func BoPVerify(pk *BoPPub, m []byte, sig *BoPSig) bool {
	if pk == nil || pk.A == nil || pk.ML == nil || sig == nil || sig.Rsp == nil || len(sig.S2) != mldsa44.SignatureSize {
		return false
	}
	chl := h2(sig.S2)
	negChl := edwards25519.NewScalar().Negate(chl)
	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negChl, pk.A, sig.Rsp)
	mp := h1(pk.A, pk.ML, m, R)
	return mldsa44.Verify(pk.ML, mp, nil, sig.S2)
}

// ResignBoP is the M1 attack against BoP-2: with only the Schnorr secret, re-sign
// using a fresh nonce k′ and reuse σ2. The verifier then recomputes R′ ≠ R, so
// h1 changes and σ2 no longer verifies; a valid σ2 would need the ML-DSA key.
func ResignBoP(skID *edwards25519.Scalar, orig *BoPSig) *BoPSig {
	chl := h2(orig.S2)
	kp := randScalar()
	rsp := edwards25519.NewScalar().MultiplyAdd(chl, skID, kp)
	return &BoPSig{Rsp: rsp, S2: orig.S2}
}

// ResignBoPM2 is a targeted M2 substitution, not a generic attack algorithm.
// It recovers the original identification commitment from the original
// response/challenge, then signs the corresponding message with the exposed
// ML-DSA key. Replacing the ML-DSA signature changes the derived challenge,
// so the unchanged identification response reconstructs a different
// commitment during verification and the substituted pair is rejected.
func ResignBoPM2(mlPriv *mldsa44.PrivateKey, pk *BoPPub, orig *BoPSig, m []byte) *BoPSig {
	neg := edwards25519.NewScalar().Negate(h2(orig.S2))
	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(neg, pk.A, orig.Rsp)
	s2 := make([]byte, mldsa44.SignatureSize)
	mldsa44.SignTo(mlPriv, h1(pk.A, pk.ML, m, R), nil, true, s2)
	return &BoPSig{Rsp: orig.Rsp, S2: s2}
}
