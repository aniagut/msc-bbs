package main

import (
	"fmt"
	"log"
	"github.com/aniagut/msc-bbs-anonymous-credentials/setup"
	"github.com/aniagut/msc-bbs-anonymous-credentials/issue"
)

func main() {
	// Example usage of the setup function
	l := 5 // Number of independent generators
	result, err := setup.Setup(l)
	if err != nil {
		log.Fatalf("Error during setup: %v", err)
	}

	fmt.Printf("Setup completed successfully!\n")
	fmt.Printf("Public Parameters: %+v\n", result.PublicParameters)
	fmt.Printf("Public Key: %+v\n", result.PublicKey)
	fmt.Printf("Secret Key: %+v\n", result.SecretKey)

	// Example usage of the issue function
	attributes := []string{"attribute1", "attribute2", "attribute3", "attribute4", "attribute5"}
	signature, err := issue.Issue(attributes, result.PublicParameters, result.SecretKey)
	if err != nil {
		log.Fatalf("Error during issuing credential: %v", err)
	}
	fmt.Printf("Credential issued successfully!\n")
	fmt.Printf("Signature: %+v\n", signature)
}