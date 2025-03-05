package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

func keyGen(n int) (*e.G1, *e.G2, *e.G1, *e.G1, *e.G1, *e.G2, []struct{
	A *e.G1 
	x e.Scalar 
}) {
	// 1. Select Generators g1 ∈ G1 and g2 ∈ G2
	g1 := e.G1Generator()
	g2 := e.G2Generator()
	fmt.Println("Generator g1: ", g1)
	fmt.Println("Generator g2: ", g2)

	// 2. Select random h ∈ G1 (excluding identity element)
	h:= randomG1Element()
	fmt.Println("Random point h: ", h)

	fmt.Println("Is h on G1? ", h.IsOnG1())

	// 3. Select random ε1, ε2 ∈ Zp*
	e1 := randomScalar()
	e2 := randomScalar()
	fmt.Println("Random scalar ε1: ", e1)
	fmt.Println("Random scalar ε2: ", e2)

	// 4. Compute u, v ∈ G1 such that u^ε1 = v^ε2 = h
	var u, v e.G1
	var inv_e1, inv_e2 e.Scalar
	inv_e1.Inv(&e1) // Compute ε1⁻¹
	inv_e2.Inv(&e2) // Compute ε2⁻¹
	// Q ? Why is this scalar multiplication?
	u.ScalarMult(&inv_e1, &h)
	v.ScalarMult(&inv_e2, &h)
	fmt.Println("Point u: ", u)
	fmt.Println("Point v: ", v)
	fmt.Println("Is u on G1? ", u.IsOnG1())
	fmt.Println("Is v on G1? ", v.IsOnG1())

	// 5. Select γ ∈ Zp* and compute w = g2^γ
	y := randomScalar()
	var w e.G2
	w.ScalarMult(&y, g2)
	fmt.Println("Random scalar γ: ", y)
	fmt.Println("Point w: ", w)

	fmt.Println("Is w on G2? ", w.IsOnG2())

	// 6. Generate SDH tuples (A_i, x_i) for each user i
	users := make([]struct {
		A *e.G1
		x e.Scalar
	}, n)

	for i := 0; i < n; i++ {
		// Select x_i ∈ Zp*
		x_i := randomScalar()

		// Compute A_i = g1^(1 / (γ + x_i))
		var y_plus_x e.Scalar
		y_plus_x.Add(&y, &x_i)   // γ + x_i
		y_plus_x.Inv(&y_plus_x)  // (γ + x_i)^(-1)

		var A_i e.G1
		A_i.ScalarMult(&y_plus_x, g1)
		fmt.Printf("Is A_%d on G1? %t\n", i, A_i.IsOnG1())

		users[i] = struct {
			A *e.G1
			x e.Scalar
		}{A: &A_i, x: x_i}
	}

	fmt.Println("\nUser Secret Keys (SDH Tuples):")
	for i, user := range users {
		fmt.Printf("User %d: A_i = %v, x_i = %v\n", i+1, user.A, user.x)
	}

	// Verify 
	// **Verification Step**
	var u_e1, v_e2 e.G1
	u_e1.ScalarMult(&e1, &u) // Compute u^ε1
	v_e2.ScalarMult(&e2, &v) // Compute v^ε2

	// Check if u^ε1 == h and v^ε2 == h
	fmt.Println("Verification:")
	fmt.Println("Does u^ε1 == h?", u_e1.IsEqual(&h))
	fmt.Println("Does v^ε2 == h?", v_e2.IsEqual(&h))

	if u_e1.IsEqual(&h) && v_e2.IsEqual(&h) {
		fmt.Println("Verification successful: u^ε1 = v^ε2 = h")
	} else {
		fmt.Println("Verification failed!")
	}

	fmt.Println("End of Key Generation")
	fmt.Println("Group public key: gpk = (g1, g2, h, u, v, w)\n")
	fmt.Printf("Group public key: gpk = (%v, %v, %v, %v, %v, %v)\n", g1, g2, h, u, v, w)

	fmt.Println("Private key of group manager: gmsk = (ε1, ε2)\n")
	fmt.Printf("Private key of group manager: gmsk = (%v, %v)\n", e1, e2)

	return g1, g2, &h, &u, &v, &w, users
}

func Sign(g1 *e.G1, g2 *e.G2, h *e.G1, u *e.G1, v *e.G1, w *e.G2, A_i *e.G1, x_i e.Scalar, M string) struct {
	T1 *e.G1
	T2 *e.G1
	T3 *e.G1
	c e.Scalar
	S_alpha *e.Scalar
	S_beta *e.Scalar
	S_x *e.Scalar
	S_delta1 *e.Scalar
	S_delta2 *e.Scalar
} {
	// Compute values for the signature
	alpha, beta := randomScalar(), randomScalar()
	delta1, delta2 := new(e.Scalar), new(e.Scalar)
	delta1.Mul(&alpha, &x_i)
	delta2.Mul(&beta, &x_i)
	r_alpha, r_beta := randomScalar(), randomScalar()
	r_x := randomScalar()
	r_delta1, r_delta2 := randomScalar(), randomScalar()

	// Compute T values
	T1 := new(e.G1)
	T1.ScalarMult(&alpha, u)
	T2 := new(e.G1)
	T2.ScalarMult(&beta, v)
	alpha_plus_beta := new(e.Scalar)
	alpha_plus_beta.Add(&alpha, &beta)
	h_alpha_beta := new(e.G1)
	h_alpha_beta.ScalarMult(alpha_plus_beta, h)
	T3 := new(e.G1)
	T3.Add(h_alpha_beta, A_i)

	// Compute R values
	R1 := new(e.G1)
	R1.ScalarMult(&r_alpha, u)
	R2 := new(e.G1)
	R2.ScalarMult(&r_beta, v)
	R3 := new(e.Gt)
	pair_1 := e.Pair(T3, g2)
	pair_1_exp := new(e.Gt)
	pair_1_exp.Exp(pair_1, &r_x)
	pair_2 := e.Pair(h, w)
	pair_2_exp := new(e.Gt)
	exp_2 := new(e.Scalar)
	exp_2.Add(&r_alpha, &r_beta)
	exp_2.Neg()
	pair_2_exp.Exp(pair_2, exp_2)
	pair_3 := e.Pair(h, g2)
	pair_3_exp := new(e.Gt)
	exp_3 := new(e.Scalar)
	exp_3.Add(&r_delta1, &r_delta2)
	exp_3.Neg()
	pair_3_exp.Exp(pair_3, exp_3)
	R3.Mul(pair_1_exp, pair_2_exp)
	R3.Mul(R3, pair_3_exp)
	R4 := new(e.G1)
	T1_rx := new(e.G1)
	T1_rx.ScalarMult(&r_x, T1)
	u_r_delta1 := new(e.G1)
	minus_r_delta1 := r_delta1
	minus_r_delta1.Neg()
	u_r_delta1.ScalarMult(&minus_r_delta1, u)
	R4.Add(T1_rx, u_r_delta1)
	R5 := new(e.G1)
	T2_rx := new(e.G1)
	T2_rx.ScalarMult(&r_x, T2)
	v_r_delta2 := new(e.G1)
	minus_r_delta2 := r_delta2
	minus_r_delta2.Neg()
	v_r_delta2.ScalarMult(&minus_r_delta2, v)
	R5.Add(T2_rx, v_r_delta2)

	c:= HashToScalar(SerializeString(M), SerializeG1(T1), SerializeG1(T2), SerializeG1(T3), SerializeG1(R1), SerializeG1(R2), SerializeGt(R3), SerializeG1(R4), SerializeG1(R5))

	// Compute s values
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
	
	// Signature
	sig := struct {
		T1 *e.G1
		T2 *e.G1
		T3 *e.G1
		c e.Scalar
		S_alpha *e.Scalar
		S_beta *e.Scalar
		S_x *e.Scalar
		S_delta1 *e.Scalar
		S_delta2 *e.Scalar
	}{T1, T2, T3, c, s_alpha, s_beta, s_x, s_delta1, s_delta2}

	return sig
}

func Verify(g1 *e.G1, g2 *e.G2, h *e.G1, u *e.G1, v *e.G1, w *e.G2, M string, signature struct{
	T1 *e.G1
	T2 *e.G1
	T3 *e.G1
	c e.Scalar
	S_alpha *e.Scalar
	S_beta *e.Scalar
	S_x *e.Scalar
	S_delta1 *e.Scalar
	S_delta2 *e.Scalar
}) bool {
	// Compute R values
	R1 := new(e.G1)
	R1.ScalarMult(signature.S_alpha, u)
	minus_c := signature.c
	minus_c.Neg()
	T1_minus_c := new(e.G1)
	T1_minus_c.ScalarMult(&minus_c, signature.T1)
	R1.Add(R1, T1_minus_c)
	R2 := new(e.G1)
	R2.ScalarMult(signature.S_beta, v)
	T2_minus_c := new(e.G1)
	T2_minus_c.ScalarMult(&minus_c, signature.T2)
	R2.Add(R2, T2_minus_c)
	R3 := new(e.Gt)
	pair_1 := e.Pair(signature.T3, g2)
	pair_1_exp := new(e.Gt)
	pair_1_exp.Exp(pair_1, signature.S_x)
	pair_2 := e.Pair(h, w)
	pair_2_exp := new(e.Gt)
	exp_2 := new(e.Scalar)
	exp_2.Add(signature.S_alpha, signature.S_beta)
	neg_exp_2 := exp_2
	neg_exp_2.Neg()
	pair_2_exp.Exp(pair_2, neg_exp_2)
	pair_3 := e.Pair(h, g2)
	pair_3_exp := new(e.Gt)
	exp_3 := new(e.Scalar)
	exp_3.Add(signature.S_delta1, signature.S_delta2)
	neg_exp_3 := exp_3
	neg_exp_3.Neg()
	pair_3_exp.Exp(pair_3, neg_exp_3)
	pair_4 := e.Pair(g1, g2)
	pair_4_exp := new(e.Gt)
	pair_4_exp.Exp(pair_4, &minus_c)
	pair_5 := e.Pair(signature.T3, w)
	pair_5_exp := new(e.Gt)
	pair_5_exp.Exp(pair_5, &signature.c)
	R3.Mul(pair_1_exp, pair_2_exp)
	R3.Mul(R3, pair_3_exp)
	R3.Mul(R3, pair_4_exp)
	R3.Mul(R3, pair_5_exp)
	R4 := new(e.G1)
	T1_s_x := new(e.G1)
	T1_s_x.ScalarMult(signature.S_x, signature.T1)
	u_s_delta1 := new(e.G1)
	minus_s_delta1 := signature.S_delta1
	minus_s_delta1.Neg()
	u_s_delta1.ScalarMult(minus_s_delta1, u)
	R4.Add(T1_s_x, u_s_delta1)
	R5 := new(e.G1)
	T2_s_x := new(e.G1)
	T2_s_x.ScalarMult(signature.S_x, signature.T2)
	v_s_delta2 := new(e.G1)
	minus_s_delta2 := signature.S_delta2
	minus_s_delta2.Neg()
	v_s_delta2.ScalarMult(minus_s_delta2, v)
	R5.Add(T2_s_x, v_s_delta2)

	// Compute c
	c:= HashToScalar(SerializeString(M), SerializeG1(signature.T1), SerializeG1(signature.T2), SerializeG1(signature.T3), SerializeG1(R1), SerializeG1(R2), SerializeGt(R3), SerializeG1(R4), SerializeG1(R5))

	// Verify
	fmt.Println("Verification:")
	fmt.Println("c: ", c)
	fmt.Println("Signature c: ", signature.c)
	fmt.Println("Does c == signature.c?", c.IsEqual(&signature.c))
	if c.IsEqual(&signature.c) == 1 {
		return true
	}
	return false
}

func HashToScalar(inputs ...[]byte) e.Scalar {
    hash := sha256.New()
    for _, input := range inputs {
        hash.Write(input)
    }
    digest := hash.Sum(nil)

    // Convert hash output into a scalar
    var scalar e.Scalar
    order := new(big.Int).SetBytes(e.Order())
    bigIntScalar := new(big.Int).SetBytes(digest)
    bigIntScalar.Mod(bigIntScalar, order) // Ensure it is in Z_p
    scalar.SetBytes(bigIntScalar.Bytes())
    
    return scalar
}

// Serialize G1 element to bytes
func SerializeG1(g *e.G1) []byte {
    return g.Bytes()
}

// Serialize G2 element to bytes
func SerializeG2(g *e.G2) []byte {
	return g.Bytes()
}

func SerializeGt(g *e.Gt) []byte {
	data, _ := g.MarshalBinary()
	return data
}

func SerializeScalar(s e.Scalar) []byte {
	data, _ := s.MarshalBinary()
	return data
}

func SerializeString(s string) []byte {
	return []byte(s)
}

func orderAsBigInt() *big.Int {
	return new(big.Int).SetBytes(e.Order())
}

// randomScalar generates a random scalar in Zp*
func randomScalar() e.Scalar {
	order:= orderAsBigInt()
	bigIntScalar, _ := rand.Int(rand.Reader, order)
	if bigIntScalar.Sign() == 0 { // Ensure it's nonzero
		return randomScalar()
	}
	var scalar e.Scalar
	scalar.SetBytes(bigIntScalar.Bytes())
	return scalar
}

// randomG1Element generates a random element in G1 by scalar multiplication of g1
// Q? is this random enough?
func randomG1Element() e.G1 {
	scalar := randomScalar()
	g1 := e.G1Generator() // Use the generator
	var h e.G1
	h.ScalarMult(&scalar, g1)
	if (h.IsIdentity()) {
		return randomG1Element()
	}
	return h
}

func createGenerators() (*e.G1, *e.G2) {
	g1, g2 := e.G1Generator(), e.G2Generator()
	return g1, g2
}

func main() {	
	g1, g2, h, u, v, w, users := keyGen(5)
	signature := Sign(g1, g2, h, u, v, w, users[0].A, users[0].x, "Hello World")
	fmt.Println("Signature: ", signature)

	verified := Verify(g1, g2, h, u, v, w, "Hello World", signature)
	fmt.Println("Is signature verified? ", verified)
}