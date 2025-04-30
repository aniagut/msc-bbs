// Package verify provides functions to verify BBS signatures.
// It includes functions to compute the necessary R values, hash the inputs to a scalar, and check the validity of the signature.
// The package uses the BLS12-381 elliptic curve for cryptographic operations.
package verify

import (
	"fmt"
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/utils"
	"github.com/aniagut/msc-bbs/models"
)

// Verify checks the validity of a BBS signature.
//
// Parameters:
//   - publicKey: The public key of the system (gpk = (g1, g2, h, u, v, w)).
//   - M: The message being verified.
//   - signature: The BBS signature to verify.
//
// Returns:
//   - bool: True if the signature is valid, false otherwise.
//   - error: An error if the verification process fails.
func Verify(publicKey models.PublicKey, M string, signature models.Signature) (bool, error) {
    // Recompute the R values based on the signature and public key
    R1 := computeR1(signature.S_alpha, publicKey.U, signature.C, signature.T1)
    R2 := computeR2(signature.S_beta, publicKey.V, signature.C, signature.T2)
    R3 := computeR3(signature.T3, publicKey.G1, publicKey.G2, signature.S_x, publicKey.H, publicKey.W, signature.S_alpha, signature.S_beta, signature.S_delta1, signature.S_delta2, signature.C)
    R4 := computeR4(signature.S_x, signature.T1, publicKey.U, signature.S_delta1)
    R5 := computeR5(signature.S_x, signature.T2, publicKey.V, signature.S_delta2)

    // Compute the challenge scalar c based on the message, commitments, and R values
    c, err := utils.HashToScalar(
        utils.SerializeString(M),
        utils.SerializeG1(signature.T1),
        utils.SerializeG1(signature.T2),
        utils.SerializeG1(signature.T3),
        utils.SerializeG1(R1),
        utils.SerializeG1(R2),
        utils.SerializeGt(R3),
        utils.SerializeG1(R4),
        utils.SerializeG1(R5),
    )
    if err != nil {
        return false, fmt.Errorf("failed to compute hash to scalar: %w", err)
    }

    // Verify that the recomputed challenge c matches the signature's challenge C
    return verifySignature(c, signature.C), nil
}

// computeR1 computes R1 = u^{s_alpha} * T1^{-c}.
func computeR1(S_alpha *e.Scalar, u *e.G1, C e.Scalar, T1 *e.G1) *e.G1 {
    R1 := new(e.G1)
    R1.ScalarMult(S_alpha, u)

    minus_c := new(e.Scalar)
    minus_c.Set(&C)
    minus_c.Neg()

    T1_minus_c := new(e.G1)
    T1_minus_c.ScalarMult(minus_c, T1)

    R1.Add(R1, T1_minus_c)
    return R1
}

// computeR2 computes R2 = v^{s_beta} * T2^{-c}.
func computeR2(S_beta *e.Scalar, v *e.G1, C e.Scalar, T2 *e.G1) *e.G1 {
    R2 := new(e.G1)
    R2.ScalarMult(S_beta, v)

    minus_c := new(e.Scalar)
    minus_c.Set(&C)
    minus_c.Neg()

    T2_minus_c := new(e.G1)
    T2_minus_c.ScalarMult(minus_c, T2)

    R2.Add(R2, T2_minus_c)
    return R2
}

// computeR3 computes R3 = e(T3, g2)^{s_x} * e(h, w)^{-s_alpha - s_beta} * e(h, g2)^{-s_delta1 - s_delta2} * (e(g1, g2) / e(T3, w))^{-c}.
func computeR3(T3 *e.G1, g1 *e.G1, g2 *e.G2, S_x *e.Scalar, h *e.G1, w *e.G2, S_alpha, S_beta, S_delta1, S_delta2 *e.Scalar, C e.Scalar) *e.Gt {
    R3 := new(e.Gt)

    // Compute e(T3, g2)^{s_x}
    T3_s_x := new(e.G1)
    T3_s_x.ScalarMult(S_x, T3)
    pair_1_exp := e.Pair(T3_s_x, g2)

    // Compute e(h, w)^{-s_alpha - s_beta}
    h_s_alpha_beta := new(e.G1)
    s_alpha_beta := new(e.Scalar)
    s_alpha_beta.Add(S_alpha, S_beta)
    s_alpha_beta.Neg()
    h_s_alpha_beta.ScalarMult(s_alpha_beta, h)
    pair_2_exp := e.Pair(h_s_alpha_beta, w)

    // Compute e(h, g2)^{-s_delta1 - s_delta2}
    h_s_delta := new(e.G1)
    s_delta := new(e.Scalar)
    s_delta.Add(S_delta1, S_delta2)
    s_delta.Neg()
    h_s_delta.ScalarMult(s_delta, h)
    pair_3_exp := e.Pair(h_s_delta, g2)

    // Compute (e(g1, g2) / e(T3, w))^{-c}
    g1_minus_c := new(e.G1)
    minus_c := new(e.Scalar)
    minus_c.Set(&C)
    minus_c.Neg()
    g1_minus_c.ScalarMult(minus_c, g1)
    pair_4_exp := e.Pair(g1_minus_c, g2)

    T3_c := new(e.G1)
    T3_c.ScalarMult(&C, T3)
    pair_5_exp := e.Pair(T3_c, w)

    // Combine all pairings
    R3.Mul(pair_1_exp, pair_2_exp)
    R3.Mul(R3, pair_3_exp)
    R3.Mul(R3, pair_4_exp)
    R3.Mul(R3, pair_5_exp)
    return R3
}

// computeR4 computes R4 = T1^{s_x} * u^{-s_delta1}.
func computeR4(S_x *e.Scalar, T1, u *e.G1, S_delta1 *e.Scalar) *e.G1 {
    R4 := new(e.G1)
    T1_s_x := new(e.G1)
    T1_s_x.ScalarMult(S_x, T1)

    u_s_delta1 := new(e.G1)
    minus_s_delta1 := new(e.Scalar)
    minus_s_delta1.Set(S_delta1)
    minus_s_delta1.Neg()
    u_s_delta1.ScalarMult(minus_s_delta1, u)

    R4.Add(T1_s_x, u_s_delta1)
    return R4
}

// computeR5 computes R5 = T2^{s_x} * v^{-s_delta2}.
func computeR5(S_x *e.Scalar, T2, v *e.G1, S_delta2 *e.Scalar) *e.G1 {
    R5 := new(e.G1)
    T2_s_x := new(e.G1)
    T2_s_x.ScalarMult(S_x, T2)

    v_s_delta2 := new(e.G1)
    minus_s_delta2 := new(e.Scalar)
    minus_s_delta2.Set(S_delta2)
    minus_s_delta2.Neg()
    v_s_delta2.ScalarMult(minus_s_delta2, v)

    R5.Add(T2_s_x, v_s_delta2)
    return R5
}

// verifySignature checks if the recomputed challenge c matches the signature's challenge C.
func verifySignature(c, C e.Scalar) bool {
    fmt.Println("Verification:")
    fmt.Println("c: ", c)
    fmt.Println("Signature c: ", C)
    fmt.Println("Does c == signature.c?", c.IsEqual(&C))
    return c.IsEqual(&C) == 1
}