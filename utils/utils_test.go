package utils

import (
    "testing"
	"math/big"

    "github.com/stretchr/testify/assert"
)

// TestRandomScalar tests the RandomScalar function.
func TestRandomScalar(t *testing.T) {
    // Generate a random scalar
    scalar, err := RandomScalar()

    // Assert no error occurred
    assert.NoError(t, err, "RandomScalar should not return an error")

    // Assert the scalar is not zero
    assert.False(t, scalar.IsZero() == 1, "RandomScalar should not generate a zero scalar")

	// Serialize the scalar to bytes
    scalarBytes, err := scalar.MarshalBinary()
    assert.NoError(t, err, "Scalar.MarshalBinary should not return an error")

	// Assert the scalar is less than the curve order
    order := OrderAsBigInt()
    scalarBigInt := new(big.Int).SetBytes(scalarBytes)
    assert.True(t, scalarBigInt.Cmp(order) < 0, "RandomScalar should be less than the curve order")
}

// TestRandomG1Element tests the RandomG1Element function.
func TestRandomG1Element(t *testing.T) {
    // Generate a random G1 element
    element, err := RandomG1Element()

    // Assert no error occurred
    assert.NoError(t, err, "RandomG1Element should not return an error")

    // Assert the element is not the identity element
    assert.False(t, element.IsIdentity(), "RandomG1Element should not generate the identity element")
}

// TestHashToScalar tests the HashToScalar function.
func TestHashToScalar(t *testing.T) {
    // Hash some inputs into a scalar
    input1 := []byte("test input 1")
    input2 := []byte("test input 2")
    scalar, err := HashToScalar(input1, input2)

    // Assert no error occurred
    assert.NoError(t, err, "HashToScalar should not return an error")

    // Assert the scalar is not zero
    assert.False(t, scalar.IsZero() == 1, "HashToScalar should not generate a zero scalar")
}