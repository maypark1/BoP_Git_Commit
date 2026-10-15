package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

func resignEd25519(edPriv ed25519.PrivateKey, m []byte) []byte {
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
	hram.Write(m)
	k, _ := edwards25519.NewScalar().SetUniformBytes(hram.Sum(nil))

	S := edwards25519.NewScalar().MultiplyAdd(k, a, r)

	sig := make([]byte, 64)
	copy(sig[:32], R.Bytes())
	copy(sig[32:], S.Bytes())
	return sig
}

func ResignConcat(edPriv ed25519.PrivateKey, orig *ConcatSig, m []byte) *ConcatSig {
	return &ConcatSig{
		S1: resignEd25519(edPriv, m),
		S2: orig.S2,
	}
}
