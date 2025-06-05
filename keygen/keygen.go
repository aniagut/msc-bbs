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
    h, err := utils.RandomG1Element()
    if err != nil {
        return models.KeyGenResult{}, err
    }

    // 3. Select random epsilon1, epsilon2 ∈ Zp*
    epsilon1, err := utils.RandomScalar()
    if err != nil {
        return models.KeyGenResult{}, err
    }
    epsilon2, err := utils.RandomScalar()
    if err != nil {
        return models.KeyGenResult{}, err
    }

    // 4. Compute u, v ∈ G1 such that u^epsilon1 = v^epsilon2 = h
    u, v := ComputeUAndV(g1, h, epsilon1, epsilon2)

    // 5. Select gamma ∈ Zp* and compute w = g2^gamma
    gamma, err := utils.RandomScalar()
    if err != nil {
        return models.KeyGenResult{}, err
    }
    w := ComputeW(g2, gamma)

    // 6. Generate SDH tuples (A_i, x_i) for each user i
    users, err := ComputeSDHTuples(n, g1, gamma)
    if err != nil {
        return models.KeyGenResult{}, err
    }

    // 7. Construct the public key
    publicKey := models.PublicKey{
        G1: g1,
        G2: g2,
        H:  &h,
        U:  &u,
        V:  &v,
        W:  &w,
    }

    // 8. Construct the secret manager key
    secretManagerKey := models.SecretManagerKey{
        Epsilon1: epsilon1,
        Epsilon2: epsilon2,
    }

    // 9. Return the result
    return models.KeyGenResult{
        PublicKey:       publicKey,
        SecretManagerKey: secretManagerKey,
        Users:           users,
    }, nil
}

// ComputeUAndV computes the elements u and v in G1 such that u^epsilon1 = v^epsilon2 = h
func ComputeUAndV(g1 *e.G1, h e.G1, epsilon1 e.Scalar, epsilon2 e.Scalar) (e.G1, e.G1) {
    // Initialize u and v as elements of G1
    var u, v e.G1

    // Compute the inverses of epsilon1 and epsilon2
    var invEpsilon1, invEpsilon2 e.Scalar
    invEpsilon1.Inv(&epsilon1) // Compute epsilon1⁻¹
    invEpsilon2.Inv(&epsilon2) // Compute epsilon2⁻¹

    // Compute u = h^(epsilon1⁻¹) and v = h^(epsilon2⁻¹)
    u.ScalarMult(&invEpsilon1, &h)
    v.ScalarMult(&invEpsilon2, &h)

    return u, v
}

// ComputeW computes w = g2^gamma, where gamma is a random scalar.
func ComputeW(g2 *e.G2, gamma e.Scalar) e.G2 {
    // Initialize w as an element of G2
    var w e.G2

    // Compute w = g2^gamma
    w.ScalarMult(&gamma, g2)

    return w
}

// ComputeSDHTuples generates n SDH tuples (A_i, x_i) for the users.
func ComputeSDHTuples(n int, g1 *e.G1, gamma e.Scalar) ([]models.User, error) {
    // Initialize a slice to store user data
    users := make([]models.User, n)

    var wg sync.WaitGroup
    errChan := make(chan error, n)

    for i := 0; i < n; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            
            // Select xI ∈ Zp* (a random scalar for the user)
            xI, err := utils.RandomScalar()
            if err != nil {
                errChan <- fmt.Errorf("failed to generate random scalar xI for user %d: %w", i, err)
                return
            }

            // Compute Ai = g1^(1 / (gamma + xI))
            Ai := ComputeAi(g1, gamma, xI)

            // Store the tuple (Ai, xI) in the users slice
            users[i] = models.User{A: &Ai, X: xI}
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

// OldComputeSDHTuples generates n SDH tuples (Ai, xI) for the users.
// This is the old version of the function, which does not use goroutines.
// It is kept for reference and may be removed in the future.
// Deprecated: Use ComputeSDHTuples instead for concurrent execution.
func OldComputeSDHTuples(n int, g1 *e.G1, gamma e.Scalar) ([]models.User, error) {
    // Initialize a slice to store user data
    users := make([]models.User, n)
    
    for i := 0; i < n; i++ {
        // Select xI ∈ Zp* (a random scalar for the user)
        xI, err := utils.RandomScalar()
        if err != nil {
            return nil, fmt.Errorf("failed to generate random scalar xI for user %d: %w", i, err)
        }
        
        // Compute Ai = g1^(1 / (gamma + xI))
        Ai := ComputeAi(g1, gamma, xI)

        // Store the tuple (Ai, xI) in the users slice
        users[i] = models.User{A: &Ai, X: xI}
    }

    return users, nil
}

// ComputeAi computes Ai = g1^(1 / (gamma + xI)) for a given user.
func ComputeAi(g1 *e.G1, gamma e.Scalar, xI e.Scalar) e.G1 {
    // Compute gamma + xI
    var gammaPlusX e.Scalar
    gammaPlusX.Add(&gamma, &xI)

    // Compute (gamma + xI)^(-1)
    gammaPlusX.Inv(&gammaPlusX)

    // Compute Ai = g1^(1 / (gamma + xI))
    var Ai e.G1
    Ai.ScalarMult(&gammaPlusX, g1)

    return Ai
}