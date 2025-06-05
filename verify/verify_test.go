package verify

import (
    "testing"

    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/aniagut/msc-bbs/models"
    "github.com/stretchr/testify/assert"
)

func TestVerify(t *testing.T) {
    // Mock public key
    publicKey := models.PublicKey{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H:  e.G1Generator(),
        U:  e.G1Generator(),
        V:  e.G1Generator(),
        W:  e.G2Generator(),
    }

    // Mock signature
    signature := models.Signature{
        T1: e.G1Generator(),
        T2: e.G1Generator(),
        T3: e.G1Generator(),
        C: func() e.Scalar {
            var scalar e.Scalar
            scalar.SetUint64(12345)
            return scalar
        }(),
        SAlpha: func() *e.Scalar {
            scalar := new(e.Scalar)
            scalar.SetUint64(1)
            return scalar
        }(),
        SBeta: func() *e.Scalar {
            scalar := new(e.Scalar)
            scalar.SetUint64(2)
            return scalar
        }(),
        SX: func() *e.Scalar {
            scalar := new(e.Scalar)
            scalar.SetUint64(3)
            return scalar
        }(),
        SDelta1: func() *e.Scalar {
            scalar := new(e.Scalar)
            scalar.SetUint64(4)
            return scalar
        }(),
        SDelta2: func() *e.Scalar {
            scalar := new(e.Scalar)
            scalar.SetUint64(5)
            return scalar
        }(),
    }

    // Mock message
    message := "Hello, world!"

    // Call the Verify function
    valid, err := Verify(publicKey, message, signature)

    // Assert no error occurred
    assert.NoError(t, err, "Verify should not return an error")

    // Assert the signature is valid
    assert.False(t, valid, "Verify should return false for mock data (invalid signature)")
}

// TestComputeR1 tests the computeR1 function.
func TestComputeR1(t *testing.T) {
    // Mock inputs
    SAlpha := new(e.Scalar)
    SAlpha.SetUint64(10)

    u := e.G1Generator()

    C := *new(e.Scalar)
    C.SetUint64(5)

    T1 := e.G1Generator()

    // Call computeR1
    R1 := computeR1(SAlpha, u, C, T1)

    // Assert R1 is not nil
    assert.NotNil(t, R1, "R1 should not be nil")
}

// TestComputeR2 tests the computeR2 function.
func TestComputeR2(t *testing.T) {
    // Mock inputs
    SBeta := new(e.Scalar)
    SBeta.SetUint64(20)

    v := e.G1Generator()

    C := *new(e.Scalar)
    C.SetUint64(5)

    T2 := e.G1Generator()

    // Call computeR2
    R2 := computeR2(SBeta, v, C, T2)

    // Assert R2 is not nil
    assert.NotNil(t, R2, "R2 should not be nil")
}

// TestComputeR3 tests the computeR3 function.
func TestComputeR3(t *testing.T) {
    // Mock inputs
    T3 := e.G1Generator()
    g1 := e.G1Generator()
    g2 := e.G2Generator()

    SX := new(e.Scalar)
    SX.SetUint64(30)

    h := e.G1Generator()
    w := e.G2Generator()

    SAlpha := new(e.Scalar)
    SAlpha.SetUint64(10)

    SBeta := new(e.Scalar)
    SBeta.SetUint64(20)

    SDelta1 := new(e.Scalar)
    SDelta1.SetUint64(15)

    SDelta2 := new(e.Scalar)
    SDelta2.SetUint64(25)

    C := *new(e.Scalar)
    C.SetUint64(5)

    // Call computeR3
    R3 := computeR3(T3, g1, g2, SX, h, w, SAlpha, SBeta, SDelta1, SDelta2, C)

    // Assert R3 is not nil
    assert.NotNil(t, R3, "R3 should not be nil")
}

// TestComputeR4 tests the computeR4 function.
func TestComputeR4(t *testing.T) {
    // Mock inputs
    SX := new(e.Scalar)
    SX.SetUint64(30)

    T1 := e.G1Generator()
    u := e.G1Generator()

    SDelta1 := new(e.Scalar)
    SDelta1.SetUint64(15)

    // Call computeR4
    R4 := computeR4(SX, T1, u, SDelta1)

    // Assert R4 is not nil
    assert.NotNil(t, R4, "R4 should not be nil")
}

// TestComputeR5 tests the computeR5 function.
func TestComputeR5(t *testing.T) {
    // Mock inputs
    SX := new(e.Scalar)
    SX.SetUint64(30)

    T2 := e.G1Generator()
    v := e.G1Generator()

    SDelta2 := new(e.Scalar)
    SDelta2.SetUint64(25)

    // Call computeR5
    R5 := computeR5(SX, T2, v, SDelta2)

    // Assert R5 is not nil
    assert.NotNil(t, R5, "R5 should not be nil")
}

// TestVerifySignature tests the verifySignature function.
func TestVerifySignature(t *testing.T) {
    // Mock inputs
    c := *new(e.Scalar)
    c.SetUint64(12345)

    C := *new(e.Scalar)
    C.SetUint64(12345)

    // Call verifySignature
    result := verifySignature(c, C)

    // Assert the result is true
    assert.True(t, result, "verifySignature should return true when c equals C")
}