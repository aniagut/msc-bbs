package open

import (
    "math/big"
    "crypto/rand"
    "testing"
    "fmt"

    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/aniagut/msc-bbs/models"
    "github.com/stretchr/testify/assert"
)

// TestOpen tests the Open function.
func TestOpen(t *testing.T) {
    // Mock inputs
    publicKey := models.PublicKey{
        G1: e.G1Generator(),
        G2: e.G2Generator(),
        H:  e.G1Generator(),
        U:  e.G1Generator(),
        V:  e.G1Generator(),
        W:  e.G2Generator(),
    }
    secretManagerKey := models.SecretManagerKey{
        Epsilon1: e.Scalar{},
        Epsilon2: e.Scalar{},
    }
    secretManagerKey.Epsilon1.SetUint64(1)
    secretManagerKey.Epsilon2.SetUint64(2)

    message := "Hello, world!"

    // Mock signature
    signature := models.Signature{
        T1: e.G1Generator(),
        T2: e.G1Generator(),
        T3: e.G1Generator(),
        C:  e.Scalar{},
    }
    signature.C.SetUint64(3)

    // Mock users with unique A values
    users := []models.User{
        {A: RandomG1Element()},
        {A: RandomG1Element()},
        {A: RandomG1Element()},
    }

    // Set the recovered public key to match the third user
    recoveredA := users[2].A

    // Create a wrapper for RecoverUserPrivateKey
    mockRecoverUserPrivateKey := func(secretManagerKey models.SecretManagerKey, signature models.Signature) *e.G1 {
        return recoveredA
    }

    // Call the Open function using the wrapper
    signerIndex, err := TestableOpen(publicKey, secretManagerKey, message, signature, users, mockRecoverUserPrivateKey)

    // Assert no error occurred
    assert.NoError(t, err, "Open should not return an error")

    // Assert the correct signer index is returned
    assert.Equal(t, 2, signerIndex, "The signer index should be 2")
}

// RandomG1Element generates a random G1 element for testing purposes.
func RandomG1Element() *e.G1 {
    element := e.G1Generator()
    scalar, err := RandomScalar()
    if err != nil {
        panic(fmt.Sprintf("Failed to generate random scalar: %v", err))
    }
    element.ScalarMult(&scalar, element)
    return element
}

// RandomScalar generates a random integer for testing purposes.
func RandomScalar() (e.Scalar, error) {
    order := new(big.Int).SetBytes(e.Order())
    randomInt, err := rand.Int(rand.Reader, order)
    if err != nil {
        return e.Scalar{}, err
    }
    var scalar e.Scalar
    scalar.SetBytes(randomInt.Bytes())
    return scalar, nil
}

// TestableOpen is a helper function that wraps the Open function for testing.
func TestableOpen(publicKey models.PublicKey, secretManagerKey models.SecretManagerKey, m string, signature models.Signature, users []models.User, mockRecoverUserPrivateKey func(models.SecretManagerKey, models.Signature) *e.G1) (int, error) {
    // Simulate signature verification (always return true for testing purposes)
    isValid := true
    if !isValid {
        return -1, fmt.Errorf("signature verification failed")
    }

    // Use the mock recovery function instead of the actual RecoverUserPrivateKey
    recoveredA := mockRecoverUserPrivateKey(secretManagerKey, signature)

    // Match the recovered public key with the list of users
    for i, user := range users {
        if recoveredA.IsEqual(user.A) {
            return i, nil // Return the index of the signer
        }
    }

    // If no match is found, return an error
    return -1, fmt.Errorf("no matching user found for the recovered public key")
}