// Package open provides functionality to verify signatures and recover user private keys in a cryptographic system.
// It includes functions to open a signature and identify the signer based on the public key and secret manager key.
// It uses the BLS12-381 elliptic curve for cryptographic operations.
package open

import (
	"fmt"
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/models"
	"github.com/aniagut/msc-bbs/verify"
)

// Open identifies the signer of a message by verifying the signature and recovering the user's public key.
//
// Parameters:
//   - publicKey: The public key of the system.
//   - secretManagerKey: The secret manager key used to recover the user's public key.
//   - M: The message that was signed.
//   - signature: The signature to verify.
//   - users: A list of users with their private keys.
//
// Returns:
//   - int: The index of the user who signed the message (0-based).
//   - error: An error if the verification or recovery fails.
func Open(publicKey models.PublicKey, secretManagerKey models.SecretManagerKey, M string, signature models.Signature, users []models.User) (int, error) {
	// Step 1: Verify the signature
	isValid, err := verify.Verify(publicKey, M, signature)
	if err != nil {
		fmt.Println("Verification failed due to an error:", err)
		return -1, err
	}
	if !isValid {
        fmt.Println("Verification failed!")
        return -1, fmt.Errorf("signature verification failed")
    }

	// Step 2: Recover the user's private key (A) from the signature
    recoveredA := RecoverUserPrivateKey(secretManagerKey, signature)

	// Step 3: Match the recovered public key with the list of users
	for i, user := range users {
		if recoveredA.IsEqual(user.A) {
			fmt.Println("User", i+1, "is the signer")
			return i, nil
		}
	}
	// If no match is found, return an error
    return -1, fmt.Errorf("no matching user found for the recovered public key")
}

// RecoverUserPrivateKey computes the user's private key (A) from the signature and the secret manager key.
//
// Parameters:
//   - secretManagerKey: The secret manager key used for recovery.
//   - signature: The signature containing the necessary components.
//
// Returns:
//   - *e.G1: The recovered private key (A).
func RecoverUserPrivateKey(secretManagerKey models.SecretManagerKey, signature models.Signature) *e.G1 {
	// Compute T1^ε1
    T1_e1 := new(e.G1)
    T1_e1.ScalarMult(&secretManagerKey.Epsilon1, signature.T1)

    // Compute T2^ε2
    T2_e2 := new(e.G1)
    T2_e2.ScalarMult(&secretManagerKey.Epsilon2, signature.T2)

    // Compute (T1^ε1 + T2^ε2)^(-1)
    T1e1_plus_T2e2 := new(e.G1)
    T1e1_plus_T2e2.Add(T1_e1, T2_e2)
    T1e1_plus_T2e2.Neg() // Compute the inverse

    // Compute A = T3 + (T1^ε1 + T2^ε2)^(-1)
    recoveredA := new(e.G1)
    recoveredA.Add(signature.T3, T1e1_plus_T2e2)

    return recoveredA
}
