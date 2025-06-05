package keygen

import (
    "testing"

    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/stretchr/testify/assert"
)

// TestKeyGen tests the KeyGen function.
func TestKeyGen(t *testing.T) {
    // Define the number of users
    n := 5

    // Call the KeyGen function
    result, err := KeyGen(n)

    // Assert no error occurred
    assert.NoError(t, err, "KeyGen should not return an error")

    // Assert the public key is not nil
    assert.NotNil(t, result.PublicKey.G1, "PublicKey.G1 should not be nil")
    assert.NotNil(t, result.PublicKey.G2, "PublicKey.G2 should not be nil")
    assert.NotNil(t, result.PublicKey.H, "PublicKey.H should not be nil")
    assert.NotNil(t, result.PublicKey.U, "PublicKey.U should not be nil")
    assert.NotNil(t, result.PublicKey.V, "PublicKey.V should not be nil")
    assert.NotNil(t, result.PublicKey.W, "PublicKey.W should not be nil")

    // Assert the secret manager key is not nil
    assert.NotNil(t, result.SecretManagerKey.Epsilon1, "SecretManagerKey.Epsilon1 should not be nil")
    assert.NotNil(t, result.SecretManagerKey.Epsilon2, "SecretManagerKey.Epsilon2 should not be nil")

    // Assert the users slice has the correct length
    assert.Equal(t, n, len(result.Users), "Users slice should have the correct length")
}

// TestComputeUAndV tests the ComputeUAndV function.
func TestComputeUAndV(t *testing.T) {
    // Define test inputs
    g1 := e.G1Generator()
    h := e.G1{}
    h.SetIdentity() // Use identity element for simplicity
    e1 := e.Scalar{}
    e1.SetUint64(1) // Set scalar to 1
    e2 := e.Scalar{}
    e2.SetUint64(2) // Set scalar to 2

    // Call the ComputeUAndV function
    u, v := ComputeUAndV(g1, h, e1, e2)

    // Assert the results are not nil
    assert.NotNil(t, u, "u should not be nil")
    assert.NotNil(t, v, "v should not be nil")

	// Verify that u^ε1 = h and v^ε2 = h
    var uCheck, vCheck e.G1
    uCheck.ScalarMult(&e1, &u)
    vCheck.ScalarMult(&e2, &v)

    assert.True(t, uCheck.IsEqual(&h), "u^ε1 should equal h")
    assert.True(t, vCheck.IsEqual(&h), "v^ε2 should equal h")
}

// TestComputeW tests the ComputeW function.
func TestComputeW(t *testing.T) {
    // Define test inputs
    g2 := e.G2Generator()
    y := e.Scalar{}
    y.SetUint64(3) // Set scalar to 3

    // Call the ComputeW function
    w := ComputeW(g2, y)

    // Assert the result is not nil
    assert.NotNil(t, w, "w should not be nil")

	// Verify that w = g2^γ
    var wCheck e.G2
    wCheck.ScalarMult(&y, g2)
    assert.True(t, wCheck.IsEqual(&w), "w should equal g2^γ")
}

// TestComputeSDHTuples tests the ComputeSDHTuples function.
func TestComputeSDHTuples(t *testing.T) {
    // Define test inputs
    n := 3
    g1 := e.G1Generator()
    y := e.Scalar{}
    y.SetUint64(4) // Set scalar to 4

    // Call the ComputeSDHTuples function
    users, err := ComputeSDHTuples(n, g1, y)

    // Assert no error occurred
    assert.NoError(t, err, "ComputeSDHTuples should not return an error")

    // Assert the users slice has the correct length
    assert.Equal(t, n, len(users), "Users slice should have the correct length")

    // Assert each user has valid A and X values
    for _, user := range users {
        assert.NotNil(t, user.A, "User.A should not be nil")
        assert.NotNil(t, user.X, "User.X should not be nil")
    }
}

// TestComputeAi tests the ComputeAi function.
func TestComputeAi(t *testing.T) {
    // Define test inputs
    g1 := e.G1Generator()
    gamma := e.Scalar{}
    gamma.SetUint64(5) // Set scalar to 5
    xI := e.Scalar{}
    xI.SetUint64(6) // Set scalar to 6

    // Call the ComputeAi function
    Ai := ComputeAi(g1, gamma, xI)

    // Assert the result is not nil
    assert.NotNil(t, Ai, "Ai should not be nil")

	// Verify that Ai = g1^(1 / (gamma + xI))
    var gammaPlusX e.Scalar
    gammaPlusX.Add(&gamma, &xI)
    gammaPlusX.Inv(&gammaPlusX)

    var aCheck e.G1
    aCheck.ScalarMult(&gammaPlusX, g1)

    assert.True(t, aCheck.IsEqual(&Ai), "Ai should equal g1^(1 / (gamma + xI))")
}