// Research-only commit model: this serializer is deliberately simpler than Git.
// It illustrates the placement of signature bytes inside the hashed object
// while keeping them outside the payload passed to the signature algorithm.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Commit is a simplified Git commit object (no committer line, single parent).
type Commit struct {
	Tree    string
	Parent  string
	Author  string
	Message string
}

// payload is the content that gets signed: the commit object without gpgsig.
func (c *Commit) payload() string {
	return fmt.Sprintf("tree %s\nparent %s\nauthor %s\n\n%s\n",
		c.Tree, c.Parent, c.Author, c.Message)
}

// withGpgsig returns the commit object with the signature embedded in a gpgsig
// header (base64 here; real Git stores an ASCII-armored OpenPGP packet).
func (c *Commit) withGpgsig(sig []byte) string {
	b64 := base64.StdEncoding.EncodeToString(sig)
	return fmt.Sprintf("tree %s\nparent %s\nauthor %s\ngpgsig %s\n\n%s\n",
		c.Tree, c.Parent, c.Author, b64, c.Message)
}

// commitHash hashes an object the way Git does: SHA-256("commit <len>\0" ‖ object).
func commitHash(objText string) string {
	header := fmt.Sprintf("commit %d\x00", len(objText))
	h := sha256.Sum256([]byte(header + objText))
	return fmt.Sprintf("%x", h)
}

// CommitHashWithSig returns the commit ID of c signed with sig. Because the
// signature is part of the hashed object, two valid signatures give two IDs.
func CommitHashWithSig(c *Commit, sig []byte) string {
	return commitHash(c.withGpgsig(sig))
}
