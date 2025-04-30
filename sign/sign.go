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
//   - M: The message to be signed.
//
// Returns:
//   - models.Signature: The generated signature.
//   - error: An error if the signing process fails.
func Sign(publicKey models.PublicKey, userPrivateKey models.User, M string) (models.Signature, error) {
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
    scalars, err := generateRandomScalars(5)
    if err != nil {
        return models.Signature{}, err
    }
    r_alpha, r_beta, r_x, r_delta1, r_delta2 := scalars[0], scalars[1], scalars[2], scalars[3], scalars[4]

	// Step 4: Compute T values
    T1, T2, T3 := ComputeTValues(alpha, beta, publicKey.H, publicKey.U, publicKey.V, userPrivateKey.A)

	// Step 5: Compute R values
    R1, R2, R3, R4, R5 := ComputeRValues(r_alpha, r_beta, r_x, r_delta1, r_delta2, T1, T2, T3, publicKey.H, publicKey.U, publicKey.V, publicKey.W, publicKey.G2)

	// Step 6: Compute challenge scalar c
    c, err := utils.HashToScalar(
        utils.SerializeString(M),
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
	s_alpha, s_beta, s_x, s_delta1, s_delta2 := ComputeSValues(alpha, beta, userPrivateKey.X, delta1, delta2, r_alpha, r_beta, r_x, r_delta1, r_delta2, c)
	
	// Step 8: Construct the signature
    signature := models.Signature{
        T1:       T1,
        T2:       T2,
        T3:       T3,
        C:        c,
        S_alpha:  s_alpha,
        S_beta:   s_beta,
        S_x:      s_x,
        S_delta1: s_delta1,
        S_delta2: s_delta2,
    }
	return signature, nil
}

// ComputeDeltas computes delta1 = alpha * x_i and delta2 = beta * x_i.
func ComputeDeltas(alpha, beta, x_i e.Scalar) (*e.Scalar, *e.Scalar) {
    delta1, delta2 := new(e.Scalar), new(e.Scalar)
    delta1.Mul(&alpha, &x_i)
    delta2.Mul(&beta, &x_i)
    return delta1, delta2
}

// ComputeTValues computes the T1, T2, and T3 values for the signature.
// T1 = u^alpha, T2 = v^beta, T3 = A_i * h^(alpha + beta).
func ComputeTValues(alpha, beta e.Scalar, h, u, v, A_i *e.G1) (*e.G1, *e.G1, *e.G1) {
    T1 := new(e.G1)
	T1.ScalarMult(&alpha, u)
	T2 := new(e.G1)
	T2.ScalarMult(&beta, v)
	T3 := ComputeT3(alpha, beta, h, A_i)
	return T1, T2, T3
}

// ComputeT3 computes T3 = A_i * h^(alpha + beta).
func ComputeT3(alpha, beta e.Scalar, h, A_i *e.G1) *e.G1 {
	alpha_plus_beta := new(e.Scalar)
	alpha_plus_beta.Add(&alpha, &beta)

	h_alpha_beta := new(e.G1)
	h_alpha_beta.ScalarMult(alpha_plus_beta, h)

	T3 := new(e.G1)
	T3.Add(h_alpha_beta, A_i)

	return T3
}

// ComputeRValues computes the R1, R2, R3, R4, and R5 values for the signature.
// R1 = u^r_alpha, R2 = v^r_beta, R3 = e(T3^(r_x), g2) * e(h^-(r_alpha + r_beta), w) * e(h^-(r_delta1 + r_delta2),
// R4 = T1^r_x * u^(-r_delta1), R5 = T2^r_x * v^(-r_delta2).
func ComputeRValues(r_alpha, r_beta, r_x, r_delta1, r_delta2 e.Scalar, T1, T2, T3, h, u, v *e.G1, w, g2 *e.G2) (*e.G1, *e.G1, *e.Gt, *e.G1, *e.G1) {
    R1 := new(e.G1)
    R1.ScalarMult(&r_alpha, u)

    R2 := new(e.G1)
    R2.ScalarMult(&r_beta, v)

    R3 := ComputeR3(T3, g2, h, w, r_x, r_alpha, r_beta, r_delta1, r_delta2)

    R4 := ComputeR4(T1, u, r_x, r_delta1)

    R5 := ComputeR5(T2, v, r_x, r_delta2)

    return R1, R2, R3, R4, R5
}

// ComputeR3 computes R3 = e(T3^(r_x), g2) * e(h^-(r_alpha + r_beta), w) * e(h^-(r_delta1 + r_delta2), g2).
func ComputeR3(T3 *e.G1, g2 *e.G2, h *e.G1, w *e.G2, r_x, r_alpha, r_beta, r_delta1, r_delta2 e.Scalar) *e.Gt {
	T3_r_x := new(e.G1)
    T3_r_x.ScalarMult(&r_x, T3)
    pair_1_exp := e.Pair(T3_r_x, g2)

    r_alpha_beta := new(e.Scalar)
    r_alpha_beta.Add(&r_alpha, &r_beta)
    r_alpha_beta.Neg()
	h_r_alpha_beta := new(e.G1)
    h_r_alpha_beta.ScalarMult(r_alpha_beta, h)
    pair_2_exp := e.Pair(h_r_alpha_beta, w)

    r_delta := new(e.Scalar)
    r_delta.Add(&r_delta1, &r_delta2)
    r_delta.Neg()
	h_r_delta := new(e.G1)
    h_r_delta.ScalarMult(r_delta, h)
    pair_3_exp := e.Pair(h_r_delta, g2)

	R3 := new(e.Gt) 
    R3.Mul(pair_1_exp, pair_2_exp)
    R3.Mul(R3, pair_3_exp)

	return R3
}

// ComputeR4 computes R4 = T1^(r_x) * u^(-r_delta1).
func ComputeR4(T1, u *e.G1, r_x, r_delta1 e.Scalar) *e.G1 {
	T1_rx := new(e.G1)
	T1_rx.ScalarMult(&r_x, T1)

	minus_r_delta1 := r_delta1
	minus_r_delta1.Neg()
	u_r_delta1 := new(e.G1)
	u_r_delta1.ScalarMult(&minus_r_delta1, u)
	
	R4 := new(e.G1)
	R4.Add(T1_rx, u_r_delta1)
	
	return R4
}

// ComputeR5 computes R5 = T2^(r_x) * v^(-r_delta2).
func ComputeR5(T2, v *e.G1, r_x, r_delta2 e.Scalar) *e.G1 {
	T2_rx := new(e.G1)
	T2_rx.ScalarMult(&r_x, T2)

	
	minus_r_delta2 := r_delta2
	minus_r_delta2.Neg()
	v_r_delta2 := new(e.G1)
	v_r_delta2.ScalarMult(&minus_r_delta2, v)
	
	R5 := new(e.G1)
	R5.Add(T2_rx, v_r_delta2)
	
	return R5
}

// ComputeSValues computes the s values for the signature.
// s_alpha = r_alpha + c * alpha, s_beta = r_beta + c * beta, s_x = r_x + c * x_i,
// s_delta1 = r_delta1 + c * delta1, s_delta2 = r_delta2 + c * delta2.
func ComputeSValues(alpha, beta e.Scalar, x_i e.Scalar, delta1, delta2 *e.Scalar, r_alpha, r_beta, r_x, r_delta1, r_delta2 e.Scalar, c e.Scalar) (*e.Scalar, *e.Scalar, *e.Scalar, *e.Scalar, *e.Scalar) {
	s_alpha := new(e.Scalar)
	s_alpha.Mul(&alpha, &c)
	s_alpha.Add(s_alpha, &r_alpha)

	s_beta := new(e.Scalar)
	s_beta.Mul(&beta, &c)
	s_beta.Add(s_beta, &r_beta)

	s_x := new(e.Scalar)
	s_x.Mul(&x_i, &c)
	s_x.Add(s_x, &r_x)

	s_delta1 := new(e.Scalar)
	s_delta1.Mul(delta1, &c)
	s_delta1.Add(s_delta1, &r_delta1)

	s_delta2 := new(e.Scalar)
	s_delta2.Mul(delta2, &c)
	s_delta2.Add(s_delta2, &r_delta2)

	return s_alpha, s_beta, s_x, s_delta1, s_delta2
}

// generateRandomScalars generates the specified number of random scalars.
func generateRandomScalars(count int) ([]e.Scalar, error) {
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