package open

import (
	"fmt"
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/models"
	"github.com/aniagut/msc-bbs/verify"
)

func Open(g1 *e.G1, g2 *e.G2, h *e.G1, u *e.G1, v *e.G1, w *e.G2, e1 e.Scalar, e2 e.Scalar, M string, signature models.Signature, users []models.User) int {
	//  Verify
	if verify.Verify(g1, g2, h, u, v, w, M, signature) == false {
		fmt.Println("Verification failed!")
		return -1
	}

	// Recover A
	A := ComputeAFromSinature(e1, e2, signature)

	// Check which user's public key matches the recovered A
	for i, user := range users {
		if A.IsEqual(user.A) {
			fmt.Println("User", i+1, "is the signer")
			return i
		}
	}
	fmt.Println("No user's public key matches the recovered A")
	return -1
}

func ComputeAFromSinature(e1 e.Scalar, e2 e.Scalar, signature models.Signature) *e.G1 {
	A := new(e.G1)

	T1_e1 := new(e.G1)
	T1_e1.ScalarMult(&e1, signature.T1)

	T2_e2 := new(e.G1)
	T2_e2.ScalarMult(&e2, signature.T2)

	T1e1_plus_T2e2 := new(e.G1)
	T1e1_plus_T2e2.Add(T1_e1, T2_e2)
	T1e1_plus_T2e2_inverse := T1e1_plus_T2e2
	T1e1_plus_T2e2_inverse.Neg()

	A.Add(signature.T3, T1e1_plus_T2e2_inverse)
	return A
}
