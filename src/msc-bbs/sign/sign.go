package sign

import (
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/utils"
	"github.com/aniagut/msc-bbs/models"
)

func Sign(g1 *e.G1, g2 *e.G2, h *e.G1, u *e.G1, v *e.G1, w *e.G2, A_i *e.G1, x_i e.Scalar, M string) models.Signature {
	// Compute helper values for the signature
	alpha, beta := utils.RandomScalar(), utils.RandomScalar()
	delta1, delta2 := ComputeDeltas(alpha, beta, x_i)

	// Compute random values r_alpha, r_beta, r_x, r_delta1, r_delta2
	r_alpha, r_beta := utils.RandomScalar(), utils.RandomScalar()
	r_x := utils.RandomScalar()
	r_delta1, r_delta2 := utils.RandomScalar(), utils.RandomScalar()

	// Compute T values
    T1, T2, T3 := ComputeTValues(alpha, beta, h, u, v, A_i)

	// Compute R values
    R1, R2, R3, R4, R5 := ComputeRValues(r_alpha, r_beta, r_x, r_delta1, r_delta2, T1, T2, T3, h, u, v, w, g2)

	c:= utils.HashToScalar(utils.SerializeString(M), utils.SerializeG1(T1), utils.SerializeG1(T2), utils.SerializeG1(T3), utils.SerializeG1(R1), utils.SerializeG1(R2), utils.SerializeGt(R3), utils.SerializeG1(R4), utils.SerializeG1(R5))

	// Compute s values
	s_alpha, s_beta, s_x, s_delta1, s_delta2 := ComputeSValues(alpha, beta, x_i, delta1, delta2, r_alpha, r_beta, r_x, r_delta1, r_delta2, c)
	
	// Signature
	signature := models.Signature{T1, T2, T3, c, s_alpha, s_beta, s_x, s_delta1, s_delta2}

	return signature
}

func ComputeDeltas(alpha, beta, x_i e.Scalar) (*e.Scalar, *e.Scalar) {
    delta1, delta2 := new(e.Scalar), new(e.Scalar)
    delta1.Mul(&alpha, &x_i)
    delta2.Mul(&beta, &x_i)
    return delta1, delta2
}

func ComputeTValues(alpha, beta e.Scalar, h, u, v, A_i *e.G1) (*e.G1, *e.G1, *e.G1) {
    T1 := new(e.G1)
    T1.ScalarMult(&alpha, u)

    T2 := new(e.G1)
    T2.ScalarMult(&beta, v)

    T3 := new(e.G1)
    T3 = ComputeT3(alpha, beta, h, A_i)
    return T1, T2, T3
}

func ComputeT3(alpha, beta e.Scalar, h, A_i *e.G1) *e.G1 {
	alpha_plus_beta := new(e.Scalar)
	alpha_plus_beta.Add(&alpha, &beta)

	h_alpha_beta := new(e.G1)
	h_alpha_beta.ScalarMult(alpha_plus_beta, h)

	T3 := new(e.G1)
	T3.Add(h_alpha_beta, A_i)

	return T3
}

func ComputeRValues(r_alpha, r_beta, r_x, r_delta1, r_delta2 e.Scalar, T1, T2, T3, h, u, v *e.G1, w, g2 *e.G2) (*e.G1, *e.G1, *e.Gt, *e.G1, *e.G1) {
    R1 := new(e.G1)
    R1.ScalarMult(&r_alpha, u)

    R2 := new(e.G1)
    R2.ScalarMult(&r_beta, v)

    R3 := ComputeR3(T3, g2, h, w, r_x, r_alpha, r_beta, r_delta1, r_delta2)

    R4 := ComputeR4(T1, u, r_x, r_delta1)

    R5 := new(e.G1)
    T2_rx := new(e.G1)
    T2_rx.ScalarMult(&r_x, T2)
    v_r_delta2 := new(e.G1)
    minus_r_delta2 := r_delta2
    minus_r_delta2.Neg()
    v_r_delta2.ScalarMult(&minus_r_delta2, v)
    R5.Add(T2_rx, v_r_delta2)
    return R1, R2, R3, R4, R5
}

func ComputeR3(T3 *e.G1, g2 *e.G2, h *e.G1, w *e.G2, r_x, r_alpha, r_beta, r_delta1, r_delta2 e.Scalar) *e.Gt {
	R3 := new(e.Gt) 
    pair_1 := e.Pair(T3, g2)
    pair_1_exp := new(e.Gt)
    pair_1_exp.Exp(pair_1, &r_x)

    pair_2 := e.Pair(h, w)
	exp_2 := new(e.Scalar)
    exp_2.Add(&r_alpha, &r_beta)
    exp_2.Neg()
    pair_2_exp := new(e.Gt)
    pair_2_exp.Exp(pair_2, exp_2)

    pair_3 := e.Pair(h, g2)
	exp_3 := new(e.Scalar)
    exp_3.Add(&r_delta1, &r_delta2)
    exp_3.Neg()
    pair_3_exp := new(e.Gt)
    pair_3_exp.Exp(pair_3, exp_3)

    R3.Mul(pair_1_exp, pair_2_exp)
    R3.Mul(R3, pair_3_exp)

	return R3
}

func ComputeR4(T1, u *e.G1, r_x, r_delta1 e.Scalar) *e.G1 {
	R4 := new(e.G1)
	T1_rx := new(e.G1)
	T1_rx.ScalarMult(&r_x, T1)
	u_r_delta1 := new(e.G1)
	minus_r_delta1 := r_delta1
	minus_r_delta1.Neg()
	u_r_delta1.ScalarMult(&minus_r_delta1, u)
	R4.Add(T1_rx, u_r_delta1)
	return R4
}

func ComputeR5(T2, v *e.G1, r_x, r_delta2 e.Scalar) *e.G1 {
	R5 := new(e.G1)
	T2_rx := new(e.G1)
	T2_rx.ScalarMult(&r_x, T2)
	v_r_delta2 := new(e.G1)
	minus_r_delta2 := r_delta2
	minus_r_delta2.Neg()
	v_r_delta2.ScalarMult(&minus_r_delta2, v)
	R5.Add(T2_rx, v_r_delta2)
	return R5
}

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