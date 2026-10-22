package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

var benchM = []byte("tree a1b2c3\nparent d4e5f6\nauthor Chanmi Park\n\ninitial commit\n")

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
		_, _ = BoPKeyGen() // <-- 네 BoP 키생성 함수명으로 맞춰라
	}
}

// ===== 공격 비용: 키 손상 재서명 =====

func BenchmarkReSign(b *testing.B) {
	pk, sk := ConcatKeyGen()
	sig := ConcatSign(sk, benchM) // 정직한 서명 1개 (네 서명 함수 시그니처에 맞춰라)
	_ = pk
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ResignConcat(sk.Ed, sig, benchM) // <-- salt 고정 재서명; 네 attack.go 함수명/인자에 맞춰라
	}
}
