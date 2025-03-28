package open

import (
	"fmt"
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/models"
	"github.com/aniagut/msc-bbs/verify"
)

func Open(publicKey models.PublicKey, secretManagerKey models.SecretManagerKey, M string, signature models.Signature, users []models.User) (int, error) {
	//  Verify
	isValid, err := verify.Verify(publicKey, M, signature)
	if err != nil {
		fmt.Println("Verification failed due to an error:", err)
		return -1, err
	}
	if !isValid {
        fmt.Println("Verification failed!")
        return -1, nil
    }

	// Recover A
	A := ComputeAFromSinature(secretManagerKey, signature)

	// Check which user's public key matches the recovered A
	for i, user := range users {
		if A.IsEqual(user.A) {
			fmt.Println("User", i+1, "is the signer")
			return i, nil
		}
	}
	fmt.Println("No user's public key matches the recovered A")
	return -1, nil
}

func ComputeAFromSinature(secretManagerKey models.SecretManagerKey, signature models.Signature) *e.G1 {
	A := new(e.G1)

	T1_e1 := new(e.G1)
	T1_e1.ScalarMult(&secretManagerKey.Epsilon1, signature.T1)

	T2_e2 := new(e.G1)
	T2_e2.ScalarMult(&secretManagerKey.Epsilon2, signature.T2)

	T1e1_plus_T2e2 := new(e.G1)
	T1e1_plus_T2e2.Add(T1_e1, T2_e2)
	T1e1_plus_T2e2_inverse := T1e1_plus_T2e2
	T1e1_plus_T2e2_inverse.Neg()

	A.Add(signature.T3, T1e1_plus_T2e2_inverse)
	return A
}
