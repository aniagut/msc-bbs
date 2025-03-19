package main

import (
	"fmt"
	"github.com/aniagut/msc-bbs/keygen"
	"github.com/aniagut/msc-bbs/sign"
	"github.com/aniagut/msc-bbs/verify"
	"github.com/aniagut/msc-bbs/open"
)

func main() {	
	g1, g2, h, u, v, w, users, e1, e2 := keygen.KeyGen(5)
	signature := sign.Sign(g1, g2, h, u, v, w, users[2].A, users[2].X, "Anna Maria Gut")

	verified := verify.Verify(g1, g2, h, u, v, w, "Anna Maria Gut", signature)
	fmt.Println("Is signature verified? ", verified)

	signer := open.Open(g1, g2, h, u, v, w, e1, e2, "Anna Maria Gut", signature, users)
	fmt.Println("Signer: ", signer + 1)
}