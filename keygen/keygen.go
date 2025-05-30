// Package keygen provides functionality for generating keys for the BBS signature scheme.
// It includes functions to generate the public key, user keys, and secret manager key.
// The package uses the BLS12-381 elliptic curve for cryptographic operations.
package keygen

import (
    e "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/aniagut/msc-bbs/utils"
	"github.com/aniagut/msc-bbs/models"
	"sync"
	"fmt"
)

// KeyGen generates the key material for the BBS signature scheme.
// 
// Parameters:
//   - n: The number of users for whom SDH tuples will be generated.
//
// Returns:
//   - KeyGenResult: A struct containing the public key, user keys, and secret manager key.
//   - error: An error if key generation fails.
func KeyGen(n int) (models.KeyGenResult, error) {
	
	// 1. Select Generators g1 ∈ G1 and g2 ∈ G2
	g1 := e.G1Generator()
	g2 := e.G2Generator()

	// 2. Select random h ∈ G1 (excluding identity element)
	h, err:= utils.RandomG1Element()
	if err != nil {
		return models.KeyGenResult{}, err
	}

	// 3. Select random ε1, ε2 ∈ Zp*
	e1, err := utils.RandomScalar()
	if err != nil {
		return models.KeyGenResult{}, err
	}
	e2, err := utils.RandomScalar()
	if err != nil {
		return models.KeyGenResult{}, err
	}

	// 4. Compute u, v ∈ G1 such that u^ε1 = v^ε2 = h
	u, v := ComputeUAndV(g1, h, e1, e2)

	// 5. Select γ ∈ Zp* and compute w = g2^γ
	y, err := utils.RandomScalar()
	if err != nil {
		return models.KeyGenResult{}, err
	}
	w := ComputeW(g2, y)

	// 6. Generate SDH tuples (A_i, x_i) for each user i
	users, err := ComputeSDHTuples(n, g1, y)
	if err != nil {
		return models.KeyGenResult{}, err
	}

	// Construct the public key
    publicKey := models.PublicKey{
        G1: g1,
        G2: g2,
        H:  &h,
        U:  &u,
        V:  &v,
        W:  &w,
    }

	// Construct the secret manager key
    secretManagerKey := models.SecretManagerKey{
        Epsilon1: e1,
        Epsilon2: e2,
    }

	// Return the result
    return models.KeyGenResult{
        PublicKey:       publicKey,
        SecretManagerKey: secretManagerKey,
        Users:           users,
    }, nil
}

// ComputeUAndV computes the elements u and v in G1 such that u^ε1 = v^ε2 = h
func ComputeUAndV(g1 *e.G1, h e.G1, e1 e.Scalar, e2 e.Scalar) (e.G1, e.G1) {
	// Initialize u and v as elements of G1
	var u, v e.G1

	// Compute the inverses of ε1 and ε2
	var inv_e1, inv_e2 e.Scalar
	inv_e1.Inv(&e1) // Compute ε1⁻¹
	inv_e2.Inv(&e2) // Compute ε2⁻¹

	// Compute u = h^(ε1⁻¹) and v = h^(ε2⁻¹)
	u.ScalarMult(&inv_e1, &h)
	v.ScalarMult(&inv_e2, &h)

	return u, v
}

// ComputeW computes w = g2^γ, where γ is a random scalar.
func ComputeW(g2 *e.G2, y e.Scalar) e.G2 {
	// Initialize w as an element of G2
	var w e.G2

	// Compute w = g2^γ
	w.ScalarMult(&y, g2)

	return w
}

// ComputeSDHTuples generates n SDH tuples (A_i, x_i) for the users.
func ComputeSDHTuples(n int, g1 *e.G1, y e.Scalar) ([]models.User, error) {
	// Initialize a slice to store user data
	users := make([]models.User, n)

	var wg sync.WaitGroup
	errChan := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			
			// Select x_i ∈ Zp* (a random scalar for the user)
			x_i, err := utils.RandomScalar()
			if err != nil {
                errChan <- fmt.Errorf("failed to generate random scalar x_i for user %d: %w", i, err)
                return
            }

			// Compute A_i = g1^(1 / (γ + x_i))
			A_i := ComputeAi(g1, y, x_i)

			// Store the tuple (A_i, x_i) in the users slice
			users[i] = models.User{A: &A_i, X: x_i}
		}(i)
	}
	wg.Wait()
	close(errChan)

	// Check if any errors occurred in the goroutines
    for err := range errChan {
        if err != nil {
            return nil, err
        }
    }

	return users, nil
}

func OldComputeSDHTuples(n int, g1 *e.G1, y e.Scalar) ([]models.User, error) {
	// Initialize a slice to store user data
	users := make([]models.User, n)
	
	for i := 0; i < n; i++ {
		// Select x_i ∈ Zp* (a random scalar for the user)
		x_i, err := utils.RandomScalar()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random scalar x_i for user %d: %w", i, err)
		}
		
		// Compute A_i = g1^(1 / (γ + x_i))
		A_i := ComputeAi(g1, y, x_i)

		// Store the tuple (A_i, x_i) in the users slice
		users[i] = models.User{A: &A_i, X: x_i}
	}

	return users, nil
}

// ComputeAi computes A_i = g1^(1 / (γ + x_i)) for a given user.
func ComputeAi(g1 *e.G1, y e.Scalar, x_i e.Scalar) e.G1 {
	// Compute γ + x_i
	var y_plus_x e.Scalar
	y_plus_x.Add(&y, &x_i)

	// Compute (γ + x_i)^(-1)
	y_plus_x.Inv(&y_plus_x)

	// Compute A_i = g1^(1 / (γ + x_i))
	var A_i e.G1
	A_i.ScalarMult(&y_plus_x, g1)

	return A_i
}
