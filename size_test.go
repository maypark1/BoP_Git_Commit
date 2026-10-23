package main

import (
	"fmt"
	"testing"
)

// Raw signature components only; salt and protocol framing excluded.
func TestSignatureSizes(t *testing.T) {
	_, cs := ConcatKeyGen()
	c := ConcatSign(cs, benchM)
	_, bs := BoPKeyGen()
	b := BoPSign(bs, benchM)
	concat := len(c.S1) + len(c.S2)
	bop := len(b.Rsp.Bytes()) + len(b.S2)
	fmt.Println("scheme,component1_bytes,mldsa44_bytes,raw_signature_bytes,salt_bytes")
	fmt.Printf("concat,%d,%d,%d,%d\n", len(c.S1), len(c.S2), concat, len(c.Salt))
	fmt.Printf("bop2,%d,%d,%d,0\n", len(b.Rsp.Bytes()), len(b.S2), bop)
	if concat != 2484 || bop != 2452 {
		t.Fatalf("unexpected sizes: %d, %d", concat, bop)
	}
}
