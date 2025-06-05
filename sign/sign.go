// Package sign provides functions to generate BBS signatures for messages using the BLS12-381 elliptic curve.
// It includes functions to compute the necessary parameters, generate random scalars, and create the final signature.
// The package uses the circl library for elliptic curve operations and the utils package for random number generation and serialization.
package sign

import (
    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/aniagut/msc-bbs/utils"
    "github.com/aniagut/msc-bbs/models"
)

// Sign generates a BBS signature for a given message.
//
// Parameters:
//   - publicKey: The public key of the system.
//   - userPrivateKey: The private key of the user signing the message.
//   - m: The message to be signed.
//
// Returns:
//   - models.Signature: The generated signature.
//   - error: An error if the signing process fails.
func Sign(publicKey models.PublicKey, userPrivateKey models.User, m string) (models.Signature, error) {
    // Step 1: Generate random scalars alpha and beta
    alpha, err := utils.RandomScalar()
    if err != nil {
        return models.Signature{}, err
    }
    beta, err := utils.RandomScalar()
    if err != nil {
        return models.Signature{}, err
    }

    // Step 2: Compute delta1 and delta2
    delta1, delta2 := ComputeDeltas(alpha, beta, userPrivateKey.X)

    // Step 3: Generate random scalars for R values
    scalars, err := GenerateRandomScalars(5)
    if err != nil {
        return models.Signature{}, err
    }
    rAlpha, rBeta, rX, rDelta1, rDelta2 := scalars[0], scalars[1], scalars[2], scalars[3], scalars[4]

    // Step 4: Compute T values
    T1, T2, T3 := ComputeTValues(alpha, beta, publicKey.H, publicKey.U, publicKey.V, userPrivateKey.A)

    // Step 5: Compute R values
    R1, R2, R3, R4, R5 := ComputeRValues(rAlpha, rBeta, rX, rDelta1, rDelta2, T1, T2, T3, publicKey.H, publicKey.U, publicKey.V, publicKey.W, publicKey.G2)

    // Step 6: Compute challenge scalar c
    c, err := utils.HashToScalar(
        utils.SerializeString(m),
        utils.SerializeG1(T1),
        utils.SerializeG1(T2),
        utils.SerializeG1(T3),
        utils.SerializeG1(R1),
        utils.SerializeG1(R2),
        utils.SerializeGt(R3),
        utils.SerializeG1(R4),
        utils.SerializeG1(R5),
    )
    if err != nil {
        return models.Signature{}, err
    }

    // Step 7: Compute s values
    sAlpha, sBeta, sX, sDelta1, sDelta2 := ComputeSValues(alpha, beta, userPrivateKey.X, delta1, delta2, rAlpha, rBeta, rX, rDelta1, rDelta2, c)
    
    // Step 8: Construct the signature
    signature := models.Signature{
        T1:      T1,
        T2:      T2,
        T3:      T3,
        C:       c,
        SAlpha:  sAlpha,
        SBeta:   sBeta,
        SX:      sX,
        SDelta1: sDelta1,
        SDelta2: sDelta2,
    }
    return signature, nil
}

// ComputeDeltas computes delta1 = alpha * x_i and delta2 = beta * x_i.
func ComputeDeltas(alpha, beta, xI e.Scalar) (*e.Scalar, *e.Scalar) {
    delta1, delta2 := new(e.Scalar), new(e.Scalar)
    delta1.Mul(&alpha, &xI)
    delta2.Mul(&beta, &xI)
    return delta1, delta2
}

// ComputeTValues computes the T1, T2, and T3 values for the signature.
// T1 = u^alpha, T2 = v^beta, T3 = A_i * h^(alpha + beta).
func ComputeTValues(alpha, beta e.Scalar, h, u, v, aI *e.G1) (*e.G1, *e.G1, *e.G1) {
    T1 := new(e.G1)
    T1.ScalarMult(&alpha, u)
    T2 := new(e.G1)
    T2.ScalarMult(&beta, v)
    T3 := ComputeT3(alpha, beta, h, aI)
    return T1, T2, T3
}

// ComputeT3 computes T3 = A_i * h^(alpha + beta).
func ComputeT3(alpha, beta e.Scalar, h, aI *e.G1) *e.G1 {
    alphaPlusBeta := new(e.Scalar)
    alphaPlusBeta.Add(&alpha, &beta)

    hAlphaBeta := new(e.G1)
    hAlphaBeta.ScalarMult(alphaPlusBeta, h)

    T3 := new(e.G1)
    T3.Add(hAlphaBeta, aI)

    return T3
}

// ComputeRValues computes the R1, R2, R3, R4, and R5 values for the signature.
// R1 = u^rAlpha, R2 = v^rBeta, R3 = e(T3^(rX), g2) * e(h^-(rAlpha + rBeta), w) * e(h^-(rDelta1 + rDelta2),
// R4 = T1^rX * u^(-rDelta1), R5 = T2^rX * v^(-rDelta2).
func ComputeRValues(rAlpha, rBeta, rX, rDelta1, rDelta2 e.Scalar, T1, T2, T3, h, u, v *e.G1, w, g2 *e.G2) (*e.G1, *e.G1, *e.Gt, *e.G1, *e.G1) {
    R1 := new(e.G1)
    R1.ScalarMult(&rAlpha, u)

    R2 := new(e.G1)
    R2.ScalarMult(&rBeta, v)

    R3 := ComputeR3(T3, g2, h, w, rX, rAlpha, rBeta, rDelta1, rDelta2)

    R4 := ComputeR4(T1, u, rX, rDelta1)

    R5 := ComputeR5(T2, v, rX, rDelta2)

    return R1, R2, R3, R4, R5
}

// ComputeR3 computes R3 = e(T3^(rX), g2) * e(h^-(rAlpha + rBeta), w) * e(h^-(rDelta1 + rDelta2), g2).
func ComputeR3(T3 *e.G1, g2 *e.G2, h *e.G1, w *e.G2, rX, rAlpha, rBeta, rDelta1, rDelta2 e.Scalar) *e.Gt {
    rAlphaBeta := new(e.Scalar)
    rAlphaBeta.Add(&rAlpha, &rBeta)
    rAlphaBeta.Neg()

    rDelta := new(e.Scalar)
    rDelta.Add(&rDelta1, &rDelta2)
    rDelta.Neg()

    R3 := e.ProdPair(
        []*e.G1{T3, h, h},
        []*e.G2{g2, w, g2},
        []*e.Scalar{&rX, rAlphaBeta, rDelta},
    )
    return R3
}

// ComputeR4 computes R4 = T1^(rX) * u^(-rDelta1).
func ComputeR4(T1, u *e.G1, rX, rDelta1 e.Scalar) *e.G1 {
    T1rX := new(e.G1)
    T1rX.ScalarMult(&rX, T1)

    minusRDelta1 := rDelta1
    minusRDelta1.Neg()
    uRDelta1 := new(e.G1)
    uRDelta1.ScalarMult(&minusRDelta1, u)
    
    R4 := new(e.G1)
    R4.Add(T1rX, uRDelta1)
    
    return R4
}

// ComputeR5 computes R5 = T2^(rX) * v^(-rDelta2).
func ComputeR5(T2, v *e.G1, rX, rDelta2 e.Scalar) *e.G1 {
    T2rX := new(e.G1)
    T2rX.ScalarMult(&rX, T2)

    minusRDelta2 := rDelta2
    minusRDelta2.Neg()
    vRDelta2 := new(e.G1)
    vRDelta2.ScalarMult(&minusRDelta2, v)
    
    R5 := new(e.G1)
    R5.Add(T2rX, vRDelta2)
    
    return R5
}

// ComputeSValues computes the s values for the signature.
// sAlpha = rAlpha + c * alpha, sBeta = rBeta + c * beta, sX = rX + c * xI,
// sDelta1 = rDelta1 + c * delta1, sDelta2 = rDelta2 + c * delta2.
func ComputeSValues(alpha, beta e.Scalar, xI e.Scalar, delta1, delta2 *e.Scalar, rAlpha, rBeta, rX, rDelta1, rDelta2, c e.Scalar) (*e.Scalar, *e.Scalar, *e.Scalar, *e.Scalar, *e.Scalar) {
    sAlpha := new(e.Scalar)
    sAlpha.Mul(&alpha, &c)
    sAlpha.Add(sAlpha, &rAlpha)

    sBeta := new(e.Scalar)
    sBeta.Mul(&beta, &c)
    sBeta.Add(sBeta, &rBeta)

    sX := new(e.Scalar)
    sX.Mul(&xI, &c)
    sX.Add(sX, &rX)

    sDelta1 := new(e.Scalar)
    sDelta1.Mul(delta1, &c)
    sDelta1.Add(sDelta1, &rDelta1)

    sDelta2 := new(e.Scalar)
    sDelta2.Mul(delta2, &c)
    sDelta2.Add(sDelta2, &rDelta2)

    return sAlpha, sBeta, sX, sDelta1, sDelta2
}

// GenerateRandomScalars generates the specified number of random scalars.
func GenerateRandomScalars(count int) ([]e.Scalar, error) {
    scalars := make([]e.Scalar, count)
    for i := 0; i < count; i++ {
        scalar, err := utils.RandomScalar()
        if err != nil {
            return nil, err
        }
        scalars[i] = scalar
    }
    return scalars, nil
}