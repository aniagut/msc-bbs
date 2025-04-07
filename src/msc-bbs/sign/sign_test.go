package sign

import (
    "testing"

    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/aniagut/msc-bbs/models"
    "github.com/stretchr/testify/assert"
)

// TestSign tests the Sign function.
func TestSign(t *testing.T) {
    publicKey := models.PublicKey{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H:  e.G1Generator(),
        U:  e.G1Generator(),
        V:  e.G1Generator(),
        W:  e.G2Generator(),
    }
    userPrivateKey := models.User{
        A: e.G1Generator(),
        X: *new(e.Scalar),
    }
    userPrivateKey.X.SetUint64(12345)

    message := "Hello, world!"

    signature, err := Sign(publicKey, userPrivateKey, message)

    assert.NoError(t, err, "Sign should not return an error")
    assert.NotNil(t, signature, "Signature should not be nil")
    assert.NotNil(t, signature.T1, "T1 should not be nil")
    assert.NotNil(t, signature.T2, "T2 should not be nil")
    assert.NotNil(t, signature.T3, "T3 should not be nil")
    assert.NotNil(t, signature.C, "Challenge scalar c should not be nil")
    assert.NotNil(t, signature.S_alpha, "s_alpha should not be nil")
    assert.NotNil(t, signature.S_beta, "s_beta should not be nil")
    assert.NotNil(t, signature.S_x, "s_x should not be nil")
    assert.NotNil(t, signature.S_delta1, "s_delta1 should not be nil")
    assert.NotNil(t, signature.S_delta2, "s_delta2 should not be nil")
}

// TestComputeDeltas tests the ComputeDeltas function.
func TestComputeDeltas(t *testing.T) {
    alpha := *new(e.Scalar)
    alpha.SetUint64(10)

    beta := *new(e.Scalar)
    beta.SetUint64(20)

    x_i := *new(e.Scalar)
    x_i.SetUint64(30)

    delta1, delta2 := ComputeDeltas(alpha, beta, x_i)

    expectedDelta1 := new(e.Scalar)
    expectedDelta1.Mul(&alpha, &x_i)

    expectedDelta2 := new(e.Scalar)
    expectedDelta2.Mul(&beta, &x_i)

    assert.Equal(t, *expectedDelta1, *delta1, "delta1 should be alpha * x_i")
    assert.Equal(t, *expectedDelta2, *delta2, "delta2 should be beta * x_i")
}

// TestComputeTValues tests the ComputeTValues function.
func TestComputeTValues(t *testing.T) {
    alpha := *new(e.Scalar)
    alpha.SetUint64(10)

    beta := *new(e.Scalar)
    beta.SetUint64(20)

    h := e.G1Generator()
    u := e.G1Generator()
    v := e.G1Generator()
    A_i := e.G1Generator()

    T1, T2, T3 := ComputeTValues(alpha, beta, h, u, v, A_i)

    expectedT1 := new(e.G1)
    expectedT1.ScalarMult(&alpha, u)

    expectedT2 := new(e.G1)
    expectedT2.ScalarMult(&beta, v)

    expectedT3 := ComputeT3(alpha, beta, h, A_i)

    assert.Equal(t, *expectedT1, *T1, "T1 should be u^alpha")
    assert.Equal(t, *expectedT2, *T2, "T2 should be v^beta")
    assert.Equal(t, *expectedT3, *T3, "T3 should be A_i * h^(alpha + beta)")
}

// TestComputeSValues tests the ComputeSValues function.
func TestComputeSValues(t *testing.T) {
    alpha := *new(e.Scalar)
    alpha.SetUint64(10)

    beta := *new(e.Scalar)
    beta.SetUint64(20)

    x_i := *new(e.Scalar)
    x_i.SetUint64(30)

    delta1 := new(e.Scalar)
    delta1.SetUint64(40)

    delta2 := new(e.Scalar)
    delta2.SetUint64(50)

    r_alpha := *new(e.Scalar)
    r_alpha.SetUint64(5)

    r_beta := *new(e.Scalar)
    r_beta.SetUint64(6)

    r_x := *new(e.Scalar)
    r_x.SetUint64(7)

    r_delta1 := *new(e.Scalar)
    r_delta1.SetUint64(8)

    r_delta2 := *new(e.Scalar)
    r_delta2.SetUint64(9)

    c := *new(e.Scalar)
    c.SetUint64(2)

    s_alpha, s_beta, s_x, s_delta1, s_delta2 := ComputeSValues(alpha, beta, x_i, delta1, delta2, r_alpha, r_beta, r_x, r_delta1, r_delta2, c)

    expectedSAlpha := new(e.Scalar)
    expectedSAlpha.Mul(&alpha, &c)
    expectedSAlpha.Add(expectedSAlpha, &r_alpha)

    expectedSBeta := new(e.Scalar)
    expectedSBeta.Mul(&beta, &c)
    expectedSBeta.Add(expectedSBeta, &r_beta)

    expectedSX := new(e.Scalar)
    expectedSX.Mul(&x_i, &c)
    expectedSX.Add(expectedSX, &r_x)

    expectedSDelta1 := new(e.Scalar)
    expectedSDelta1.Mul(delta1, &c)
    expectedSDelta1.Add(expectedSDelta1, &r_delta1)

    expectedSDelta2 := new(e.Scalar)
    expectedSDelta2.Mul(delta2, &c)
    expectedSDelta2.Add(expectedSDelta2, &r_delta2)

    assert.Equal(t, *expectedSAlpha, *s_alpha, "s_alpha should be r_alpha + c * alpha")
    assert.Equal(t, *expectedSBeta, *s_beta, "s_beta should be r_beta + c * beta")
    assert.Equal(t, *expectedSX, *s_x, "s_x should be r_x + c * x_i")
    assert.Equal(t, *expectedSDelta1, *s_delta1, "s_delta1 should be r_delta1 + c * delta1")
    assert.Equal(t, *expectedSDelta2, *s_delta2, "s_delta2 should be r_delta2 + c * delta2")
}