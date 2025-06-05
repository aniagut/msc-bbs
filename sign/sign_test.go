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
    assert.NotNil(t, signature.SAlpha, "sAlpha should not be nil")
    assert.NotNil(t, signature.SBeta, "sBeta should not be nil")
    assert.NotNil(t, signature.SX, "sX should not be nil")
    assert.NotNil(t, signature.SDelta1, "sDelta1 should not be nil")
    assert.NotNil(t, signature.SDelta2, "sDelta2 should not be nil")
}

// TestComputeDeltas tests the ComputeDeltas function.
func TestComputeDeltas(t *testing.T) {
    alpha := *new(e.Scalar)
    alpha.SetUint64(10)

    beta := *new(e.Scalar)
    beta.SetUint64(20)

    xI := *new(e.Scalar)
    xI.SetUint64(30)

    delta1, delta2 := ComputeDeltas(alpha, beta, xI)

    expectedDelta1 := new(e.Scalar)
    expectedDelta1.Mul(&alpha, &xI)

    expectedDelta2 := new(e.Scalar)
    expectedDelta2.Mul(&beta, &xI)

    assert.Equal(t, *expectedDelta1, *delta1, "delta1 should be alpha * xI")
    assert.Equal(t, *expectedDelta2, *delta2, "delta2 should be beta * xI")
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
    aI := e.G1Generator()

    T1, T2, T3 := ComputeTValues(alpha, beta, h, u, v, aI)

    expectedT1 := new(e.G1)
    expectedT1.ScalarMult(&alpha, u)

    expectedT2 := new(e.G1)
    expectedT2.ScalarMult(&beta, v)

    expectedT3 := ComputeT3(alpha, beta, h, aI)

    assert.Equal(t, *expectedT1, *T1, "T1 should be u^alpha")
    assert.Equal(t, *expectedT2, *T2, "T2 should be v^beta")
    assert.Equal(t, *expectedT3, *T3, "T3 should be aI * h^(alpha + beta)")
}

// TestComputeSValues tests the ComputeSValues function.
func TestComputeSValues(t *testing.T) {
    alpha := *new(e.Scalar)
    alpha.SetUint64(10)

    beta := *new(e.Scalar)
    beta.SetUint64(20)

    xI := *new(e.Scalar)
    xI.SetUint64(30)

    delta1 := new(e.Scalar)
    delta1.SetUint64(40)

    delta2 := new(e.Scalar)
    delta2.SetUint64(50)

    rAlpha := *new(e.Scalar)
    rAlpha.SetUint64(5)

    rBeta := *new(e.Scalar)
    rBeta.SetUint64(6)

    rX := *new(e.Scalar)
    rX.SetUint64(7)

    rDelta1 := *new(e.Scalar)
    rDelta1.SetUint64(8)

    rDelta2 := *new(e.Scalar)
    rDelta2.SetUint64(9)

    c := *new(e.Scalar)
    c.SetUint64(2)

    sAlpha, sBeta, sX, sDelta1, sDelta2 := ComputeSValues(alpha, beta, xI, delta1, delta2, rAlpha, rBeta, rX, rDelta1, rDelta2, c)

    expectedSAlpha := new(e.Scalar)
    expectedSAlpha.Mul(&alpha, &c)
    expectedSAlpha.Add(expectedSAlpha, &rAlpha)

    expectedSBeta := new(e.Scalar)
    expectedSBeta.Mul(&beta, &c)
    expectedSBeta.Add(expectedSBeta, &rBeta)

    expectedSX := new(e.Scalar)
    expectedSX.Mul(&xI, &c)
    expectedSX.Add(expectedSX, &rX)

    expectedSDelta1 := new(e.Scalar)
    expectedSDelta1.Mul(delta1, &c)
    expectedSDelta1.Add(expectedSDelta1, &rDelta1)

    expectedSDelta2 := new(e.Scalar)
    expectedSDelta2.Mul(delta2, &c)
    expectedSDelta2.Add(expectedSDelta2, &rDelta2)

    assert.Equal(t, *expectedSAlpha, *sAlpha, "sAlpha should be rAlpha + c * alpha")
    assert.Equal(t, *expectedSBeta, *sBeta, "sBeta should be rBeta + c * beta")
    assert.Equal(t, *expectedSX, *sX, "sX should be rX + c * xI")
    assert.Equal(t, *expectedSDelta1, *sDelta1, "sDelta1 should be rDelta1 + c * delta1")
    assert.Equal(t, *expectedSDelta2, *sDelta2, "sDelta2 should be rDelta2 + c * delta2")
}