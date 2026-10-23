package main

import "testing"

// Heap allocation benchmarks: B/op and allocs/op; not peak RSS.
func BenchmarkMemoryConcatSign(b *testing.B) {
	_, sk := ConcatKeyGen()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ConcatSign(sk, benchM)
	}
}
func BenchmarkMemoryConcatVerify(b *testing.B) {
	pk, sk := ConcatKeyGen()
	s := ConcatSign(sk, benchM)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ConcatVerify(pk, benchM, s)
	}
}
func BenchmarkMemoryBoPSign(b *testing.B) {
	_, sk := BoPKeyGen()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BoPSign(sk, benchM)
	}
}
func BenchmarkMemoryBoPVerify(b *testing.B) {
	pk, sk := BoPKeyGen()
	s := BoPSign(sk, benchM)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BoPVerify(pk, benchM, s)
	}
}
