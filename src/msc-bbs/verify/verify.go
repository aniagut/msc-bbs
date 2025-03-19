package verify

import (
	"fmt"
	e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/utils"
	"github.com/aniagut/msc-bbs/models"
)

func Verify(g1 *e.G1, g2 *e.G2, h *e.G1, u *e.G1, v *e.G1, w *e.G2, M string, signature models.Signature) bool {
    // Compute R values
    R1 := computeR1(signature.S_alpha, u, signature.C, signature.T1)
    R2 := computeR2(signature.S_beta, v, signature.C, signature.T2)
    R3 := computeR3(signature.T3, g1, g2, signature.S_x, h, w, signature.S_alpha, signature.S_beta, signature.S_delta1, signature.S_delta2, signature.C)
    R4 := computeR4(signature.S_x, signature.T1, u, signature.S_delta1)
    R5 := computeR5(signature.S_x, signature.T2, v, signature.S_delta2)

    // Compute c
    c := utils.HashToScalar(utils.SerializeString(M), utils.SerializeG1(signature.T1), utils.SerializeG1(signature.T2), utils.SerializeG1(signature.T3), utils.SerializeG1(R1), utils.SerializeG1(R2), utils.SerializeGt(R3), utils.SerializeG1(R4), utils.SerializeG1(R5))

    // Verify
    return verifySignature(c, signature.C)
}

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

func computeR3(T3 *e.G1, g1 *e.G1, g2 *e.G2, S_x *e.Scalar, h *e.G1, w *e.G2, S_alpha, S_beta, S_delta1, S_delta2 *e.Scalar, C e.Scalar) *e.Gt {
    R3 := new(e.Gt)
    pair_1 := e.Pair(T3, g2)
    pair_1_exp := new(e.Gt)
    pair_1_exp.Exp(pair_1, S_x)
    pair_2 := e.Pair(h, w)
    pair_2_exp := new(e.Gt)
    exp_2 := new(e.Scalar)
    exp_2.Add(S_alpha, S_beta)
    neg_exp_2 := new(e.Scalar)
    neg_exp_2.Set(exp_2)
    neg_exp_2.Neg()
    pair_2_exp.Exp(pair_2, neg_exp_2)
    pair_3 := e.Pair(h, g2)
    pair_3_exp := new(e.Gt)
    exp_3 := new(e.Scalar)
    exp_3.Add(S_delta1, S_delta2)
    neg_exp_3 := new(e.Scalar)
    neg_exp_3.Set(exp_3)
    neg_exp_3.Neg()
    pair_3_exp.Exp(pair_3, neg_exp_3)
    pair_4 := e.Pair(g1, g2)
    pair_4_exp := new(e.Gt)
    minus_c := new(e.Scalar)
    minus_c.Set(&C)
    minus_c.Neg()
    pair_4_exp.Exp(pair_4, minus_c)
    pair_5 := e.Pair(T3, w)
    pair_5_exp := new(e.Gt)
    pair_5_exp.Exp(pair_5, &C)
    R3.Mul(pair_1_exp, pair_2_exp)
    R3.Mul(R3, pair_3_exp)
    R3.Mul(R3, pair_4_exp)
    R3.Mul(R3, pair_5_exp)
    return R3
}

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

func verifySignature(c, C e.Scalar) bool {
    fmt.Println("Verification:")
    fmt.Println("c: ", c)
    fmt.Println("Signature c: ", C)
    fmt.Println("Does c == signature.c?", c.IsEqual(&C))
    return c.IsEqual(&C) == 1
}