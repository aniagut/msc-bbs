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
    R1 := computeR1(signature.SAlpha, publicKey.U, signature.C, signature.T1)
    R2 := computeR2(signature.SBeta, publicKey.V, signature.C, signature.T2)
    R3 := computeR3(signature.T3, publicKey.G1, publicKey.G2, signature.SX, publicKey.H, publicKey.W, signature.SAlpha, signature.SBeta, signature.SDelta1, signature.SDelta2, signature.C)
    R4 := computeR4(signature.SX, signature.T1, publicKey.U, signature.SDelta1)
    R5 := computeR5(signature.SX, signature.T2, publicKey.V, signature.SDelta2)

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
func computeR1(SAlpha *e.Scalar, u *e.G1, C e.Scalar, T1 *e.G1) *e.G1 {
    R1 := new(e.G1)
    R1.ScalarMult(SAlpha, u)

    minusC := new(e.Scalar)
    minusC.Set(&C)
    minusC.Neg()

    T1MinusC := new(e.G1)
    T1MinusC.ScalarMult(minusC, T1)

    R1.Add(R1, T1MinusC)
    return R1
}

// computeR2 computes R2 = v^{s_beta} * T2^{-c}.
func computeR2(SBeta *e.Scalar, v *e.G1, C e.Scalar, T2 *e.G1) *e.G1 {
    R2 := new(e.G1)
    R2.ScalarMult(SBeta, v)

    minusC := new(e.Scalar)
    minusC.Set(&C)
    minusC.Neg()

    T2MinusC := new(e.G1)
    T2MinusC.ScalarMult(minusC, T2)

    R2.Add(R2, T2MinusC)
    return R2
}

// computeR3 computes R3 = e(T3, g2)^{s_x} * e(h, w)^{-s_alpha - s_beta} * e(h, g2)^{-s_delta1 - s_delta2} * (e(g1, g2) / e(T3, w))^{-c}.
func computeR3(T3 *e.G1, g1 *e.G1, g2 *e.G2, SX *e.Scalar, h *e.G1, w *e.G2, SAlpha, SBeta, SDelta1, SDelta2 *e.Scalar, C e.Scalar) *e.Gt {
    // Compute (-s_alpha - s_beta)
    sAlphaBeta := new(e.Scalar)
    sAlphaBeta.Add(SAlpha, SBeta)
    sAlphaBeta.Neg()

    // Compute (-s_delta1 - s_delta2)
    sDelta := new(e.Scalar)
    sDelta.Add(SDelta1, SDelta2)
    sDelta.Neg()

    // Compute {-c}
    minusC := new(e.Scalar)
    minusC.Set(&C)
    minusC.Neg()

    R3 := e.ProdPair(
        []*e.G1{T3, h, h, g1, T3},
        []*e.G2{g2, w, g2, g2, w},
        []*e.Scalar{SX, sAlphaBeta, sDelta, minusC, &C},
    )
    return R3
}

// computeR4 computes R4 = T1^{s_x} * u^{-s_delta1}.
func computeR4(SX *e.Scalar, T1, u *e.G1, SDelta1 *e.Scalar) *e.G1 {
    R4 := new(e.G1)
    T1SX := new(e.G1)
    T1SX.ScalarMult(SX, T1)

    uSDelta1 := new(e.G1)
    minusSDelta1 := new(e.Scalar)
    minusSDelta1.Set(SDelta1)
    minusSDelta1.Neg()
    uSDelta1.ScalarMult(minusSDelta1, u)

    R4.Add(T1SX, uSDelta1)
    return R4
}

// computeR5 computes R5 = T2^{s_x} * v^{-s_delta2}.
func computeR5(SX *e.Scalar, T2, v *e.G1, SDelta2 *e.Scalar) *e.G1 {
    R5 := new(e.G1)
    T2SX := new(e.G1)
    T2SX.ScalarMult(SX, T2)

    vSDelta2 := new(e.G1)
    minusSDelta2 := new(e.Scalar)
    minusSDelta2.Set(SDelta2)
    minusSDelta2.Neg()
    vSDelta2.ScalarMult(minusSDelta2, v)

    R5.Add(T2SX, vSDelta2)
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