package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// benchM is the same commit payload the demo signs (see Commit.payload).
var benchM = []byte("tree a1b2c3\nparent d4e5f6\nauthor Chanmi Park\n\ninitial commit\n")

// ===== Sign / Verify =====

func BenchmarkMLDSASign(b *testing.B) {
	_, sk, _ := mldsa44.GenerateKey(rand.Reader)
	sig := make([]byte, mldsa44.SignatureSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mldsa44.SignTo(sk, benchM, nil, false, sig)
	}
}

func BenchmarkMLDSAVerify(b *testing.B) {
	pub, sk, _ := mldsa44.GenerateKey(rand.Reader)
	sig := make([]byte, mldsa44.SignatureSize)
	mldsa44.SignTo(sk, benchM, nil, false, sig)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mldsa44.Verify(pub, benchM, nil, sig)
	}
}

func BenchmarkConcatSign(b *testing.B) {
	_, sk := ConcatKeyGen()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConcatSign(sk, benchM)
	}
}

func BenchmarkConcatVerify(b *testing.B) {
	pk, sk := ConcatKeyGen()
	sig := ConcatSign(sk, benchM)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConcatVerify(pk, benchM, sig)
	}
}

func BenchmarkBoPSign(b *testing.B) {
	_, sk := BoPKeyGen()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BoPSign(sk, benchM)
	}
}

func BenchmarkBoPVerify(b *testing.B) {
	pk, sk := BoPKeyGen()
	sig := BoPSign(sk, benchM)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BoPVerify(pk, benchM, sig)
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(priv, benchM)
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, benchM)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, benchM, sig)
	}
}

// ===== KeyGen =====

func BenchmarkMLDSAKeyGen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = mldsa44.GenerateKey(rand.Reader)
	}
}

func BenchmarkEd25519KeyGen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = ed25519.GenerateKey(rand.Reader)
	}
}

func BenchmarkConcatKeyGen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ConcatKeyGen() // returns (pub, priv)
	}
}

func BenchmarkBoPKeyGen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = BoPKeyGen() // returns (pub, priv)
	}
}

// ===== Attack cost: key-compromise re-signing (M1) =====

// BenchmarkReSign measures the attacker's cost to forge a second valid concat
// signature: only the Ed25519 component is recomputed, σ2 is reused as is.
func BenchmarkReSign(b *testing.B) {
	_, sk := ConcatKeyGen()
	sig := ConcatSign(sk, benchM) // one honest signature to re-sign
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ResignConcat(sk.Ed, sig, benchM) // salt fixed, Ed25519 re-signed, σ2 reused
	}
}
