package main

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type ConcatPub struct {
	Ed ed25519.PublicKey
	ML *mldsa44.PublicKey
}

type ConcatPriv struct {
	Ed ed25519.PrivateKey
	ML *mldsa44.PrivateKey
}

type ConcatSig struct {
	S1 []byte
	S2 []byte
}

func (s *ConcatSig) Bytes() []byte {
	return append(append([]byte{}, s.S1...), s.S2...)
}

func ConcatKeyGen() (*ConcatPub, *ConcatPriv) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	mlPub, mlPriv, _ := mldsa44.GenerateKey(rand.Reader)
	return &ConcatPub{edPub, mlPub}, &ConcatPriv{edPriv, mlPriv}
}

func ConcatSign(sk *ConcatPriv, m []byte) *ConcatSig {
	s1 := ed25519.Sign(sk.Ed, m)
	s2 := make([]byte, mldsa44.SignatureSize)
	mldsa44.SignTo(sk.ML, m, nil, false, s2)
	return &ConcatSig{S1: s1, S2: s2}
}

func ConcatVerify(pk *ConcatPub, m []byte, sig *ConcatSig) bool {
	v1 := ed25519.Verify(pk.Ed, m, sig.S1)
	v2 := mldsa44.Verify(pk.ML, m, nil, sig.S2)
	return v1 && v2
}
