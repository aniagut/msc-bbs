package main

import (
	"fmt"
	"github.com/aniagut/msc-bbs/keygen"
	"github.com/aniagut/msc-bbs/sign"
	"github.com/aniagut/msc-bbs/verify"
	"github.com/aniagut/msc-bbs/open"
)

func main() {	
	result, err := keygen.KeyGen(5)

	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	publicKey, users, secretManagerKey := result.PublicKey, result.Users, result.SecretManagerKey
	signature, err := sign.Sign(publicKey, users[2], "Anna Maria Gut")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	verified, err := verify.Verify(publicKey, "Anna Maria Gut", signature)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Println("Is signature verified? ", verified)

	signer, err := open.Open(publicKey, secretManagerKey, "Anna Maria Gut", signature, users)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Println("Signer: ", signer + 1)
}