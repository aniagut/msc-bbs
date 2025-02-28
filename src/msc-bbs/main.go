package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

func keyGen(n int) {
	// 1. Select Generators g1 ∈ G1 and g2 ∈ G2
	g1 := e.G1Generator()
	g2 := e.G2Generator()
	fmt.Println("Generator g1: ", g1)
	fmt.Println("Generator g2: ", g2)

	// 2. Select random h ∈ G1 (excluding identity element)
	h:= randomG1Element()
	fmt.Println("Random point h: ", h)

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
	u.Exp(h, inv_e1)
	v.Exp(h, inv_e2)
	fmt.Println("Point u: ", u)
	fmt.Println("Point v: ", v)

	// 5. Select γ ∈ Zp* and compute w = g2^γ
	y := randomScalar()
	var w e.Gt
	w.Exp(g2, y)
	fmt.Println("Random scalar γ: ", y)
	fmt.Println("Point w: ", w)

	// 6. Generate SDH tuples (A_i, x_i) for each user i
	users := make([]struct {
		A e.G1
		x e.Scalar
	}, n)

	for i := 0; i < n; i++ {
		// Select x_i ∈ Zp*
		x_i := randomScalar()

		// Compute A_i = g1^(1 / (γ + x_i))
		var y_plus_x e.Scalar
		y_plus_x.Add(&y, &x_i)   // γ + x_i
		y_plus_x.Inv(&y_plus_x)  // (γ + x_i)^(-1)

		var A_i e.Gt
		A_i.Exp(g1, y_plus_x)

		users[i] = struct {
			A e.G1
			x e.Scalar
		}{A: A_i, x: x_i}
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
func randomG1Element() e.G1 {
	scalar := randomScalar()
	g1 := e.G1Generator() // Use the generator
	var h e.G1
	h.ScalarMult(&scalar, g1)
	return h
}

func createGenerators() (*e.G1, *e.G2) {
	g1, g2 := e.G1Generator(), e.G2Generator()
	return g1, g2
}

func main() {	
	keyGen(5)
}