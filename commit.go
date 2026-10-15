package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type Commit struct {
	Tree    string
	Parent  string
	Author  string
	Message string
}

func (c *Commit) payload() string {
	return fmt.Sprintf("tree %s\nparent %s\nauthor %s\n\n%s\n",
		c.Tree, c.Parent, c.Author, c.Message)
}

func (c *Commit) withGpgsig(sig []byte) string {
	b64 := base64.StdEncoding.EncodeToString(sig)
	return fmt.Sprintf("tree %s\nparent %s\nauthor %s\ngpgsig %s\n\n%s\n",
		c.Tree, c.Parent, c.Author, b64, c.Message)
}

func commitHash(objText string) string {
	header := fmt.Sprintf("commit %d\x00", len(objText))
	h := sha256.Sum256([]byte(header + objText))
	return fmt.Sprintf("%x", h)
}

func CommitHashWithSig(c *Commit, sig []byte) string {
	return commitHash(c.withGpgsig(sig))
}
