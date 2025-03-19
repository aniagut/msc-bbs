package keygen

import (
    e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/utils"
	"github.com/aniagut/msc-bbs/models"
)

func KeyGen(n int) (*e.G1, *e.G2, *e.G1, *e.G1, *e.G1, *e.G2, []models.User, e.Scalar, e.Scalar) {
	
	// 1. Select Generators g1 ∈ G1 and g2 ∈ G2
	g1 := e.G1Generator()
	g2 := e.G2Generator()

	// 2. Select random h ∈ G1 (excluding identity element)
	h:= utils.RandomG1Element()

	// 3. Select random ε1, ε2 ∈ Zp*
	e1 := utils.RandomScalar()
	e2 := utils.RandomScalar()

	// 4. Compute u, v ∈ G1 such that u^ε1 = v^ε2 = h
	u, v := ComputeUAndV(g1, h, e1, e2)

	// 5. Select γ ∈ Zp* and compute w = g2^γ
	y := utils.RandomScalar()
	w := ComputeW(g2, y)

	// 6. Generate SDH tuples (A_i, x_i) for each user i
	users := ComputeSDHTuples(n, g1, y)

	return g1, g2, &h, &u, &v, &w, users, e1, e2 
}

func ComputeUAndV(g1 *e.G1, h e.G1, e1 e.Scalar, e2 e.Scalar) (e.G1, e.G1) {
	// Compute u, v ∈ G1 such that u^ε1 = v^ε2 = h
	var u, v e.G1
	var inv_e1, inv_e2 e.Scalar
	inv_e1.Inv(&e1) // Compute ε1⁻¹
	inv_e2.Inv(&e2) // Compute ε2⁻¹

	u.ScalarMult(&inv_e1, &h)
	v.ScalarMult(&inv_e2, &h)

	return u, v
}

func ComputeW(g2 *e.G2, y e.Scalar) e.G2 {
	// Compute w = g2^γ
	var w e.G2
	w.ScalarMult(&y, g2)
	return w
}

func ComputeSDHTuples(n int, g1 *e.G1, y e.Scalar) []models.User {
	users := make([]models.User, n)

	for i := 0; i < n; i++ {
		// Select x_i ∈ Zp*
		x_i := utils.RandomScalar()

		// Compute A_i = g1^(1 / (γ + x_i))
		A_i := ComputeAi(g1, y, x_i)
		// fmt.Printf("Is A_%d on G1? %t\n", i, A_i.IsOnG1())

		users[i] = models.User{A: &A_i, X: x_i}
	}
	return users
}

func ComputeAi(g1 *e.G1, y e.Scalar, x_i e.Scalar) e.G1 {
	// Compute A_i = g1^(1 / (γ + x_i))
	var y_plus_x e.Scalar
	y_plus_x.Add(&y, &x_i)   // γ + x_i
	y_plus_x.Inv(&y_plus_x)  // (γ + x_i)^(-1)

	var A_i e.G1
	A_i.ScalarMult(&y_plus_x, g1)
	return A_i
}
