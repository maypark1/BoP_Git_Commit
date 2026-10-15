package main

import (
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"filippo.io/edwars25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

type BoPPub struct {
	A *edwards25519.Point
	ML *mldsa44.PublicKey
}

type BoPPriv struct {
	a *edwards25519.Scalar
	A *edwards25519.Point
	ML *
}
