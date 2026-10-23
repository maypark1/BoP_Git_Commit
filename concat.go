package main

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// composite signature algorithm ID (RFC 9980-style domain tag), illustrative
var algID = []byte{0x23}

const saltLen = 16 // v6 signature salt

type ConcatPub struct {
	Ed ed25519.PublicKey
	ML *mldsa44.PublicKey
}
type ConcatPriv struct {
	Ed ed25519.PrivateKey
	ML *mldsa44.PrivateKey
}
type ConcatSig struct {
	Salt []byte
	S1   []byte // Ed25519 component
	S2   []byte // ML-DSA component
}

func (s *ConcatSig) Bytes() []byte {
	out := append([]byte{}, s.Salt...)
	out = append(out, s.S1...)
	out = append(out, s.S2...)
	return out
}

// the input BOTH components sign: salt ‖ algID ‖ m  (models RFC 9980 v6 hashed data)
func hashedInput(salt, m []byte) []byte {
	in := append([]byte{}, salt...)
	in = append(in, algID...)
	in = append(in, m...)
	return in
}

func ConcatKeyGen() (*ConcatPub, *ConcatPriv) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	mlPub, mlPriv, _ := mldsa44.GenerateKey(rand.Reader)
	return &ConcatPub{edPub, mlPub}, &ConcatPriv{edPriv, mlPriv}
}

func ConcatSign(sk *ConcatPriv, m []byte) *ConcatSig {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	in := hashedInput(salt, m)
	s1 := ed25519.Sign(sk.Ed, in)
	s2 := make([]byte, mldsa44.SignatureSize)
	mldsa44.SignTo(sk.ML, in, nil, false, s2)
	return &ConcatSig{Salt: salt, S1: s1, S2: s2}
}

func ConcatVerify(pk *ConcatPub, m []byte, sig *ConcatSig) bool {
	if pk == nil || pk.ML == nil || sig == nil || len(sig.Salt) != saltLen || len(sig.S1) != ed25519.SignatureSize || len(sig.S2) != mldsa44.SignatureSize {
		return false
	}
	in := hashedInput(sig.Salt, m)
	v1 := ed25519.Verify(pk.Ed, in, sig.S1)
	v2 := mldsa44.Verify(pk.ML, in, nil, sig.S2)
	return v1 && v2
}
