package main

import (
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type BoPPub struct {
	A  *edwards25519.Point
	ML *mldsa44.PublicKey
}
type BoPPriv struct {
	a  *edwards25519.Scalar
	A  *edwards25519.Point
	ML *mldsa44.PrivateKey
}
type BoPSig struct {
	Rsp *edwards25519.Scalar
	S2  []byte
}

func randScalar() *edwards25519.Scalar {
	b := make([]byte, 64)
	rand.Read(b)
	s, _ := edwards25519.NewScalar().SetUniformBytes(b)
	return s
}

func BoPKeyGen() (*BoPPub, *BoPPriv) {
	a := randScalar()
	A := new(edwards25519.Point).ScalarBaseMult(a)
	mlPub, mlPriv, _ := mldsa44.GenerateKey(rand.Reader)
	return &BoPPub{A, mlPub}, &BoPPriv{a, A, mlPriv}
}

func h1(A *edwards25519.Point, mlPub *mldsa44.PublicKey, m []byte, R *edwards25519.Point) []byte {
	pk2, _ := mlPub.MarshalBinary()
	h := sha512.New()
	h.Write(A.Bytes())
	h.Write(pk2)
	h.Write(m)
	h.Write(R.Bytes())
	return h.Sum(nil)
}

func h2(sig2 []byte) *edwards25519.Scalar {
	d := sha512.Sum512(sig2)
	c, _ := edwards25519.NewScalar().SetUniformBytes(d[:])
	return c
}

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

func BoPVerify(pk *BoPPub, m []byte, sig *BoPSig) bool {
	chl := h2(sig.S2)
	negChl := edwards25519.NewScalar().Negate(chl)
	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negChl, pk.A, sig.Rsp)
	mp := h1(pk.A, pk.ML, m, R)
	return mldsa44.Verify(pk.ML, mp, nil, sig.S2)
}

func ResignBoP(skID *edwards25519.Scalar, orig *BoPSig) *BoPSig {
	chl := h2(orig.S2)
	kp := randScalar()
	rsp := edwards25519.NewScalar().MultiplyAdd(chl, skID, kp)
	return &BoPSig{Rsp: rsp, S2: orig.S2}
}
