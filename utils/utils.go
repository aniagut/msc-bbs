// Package utils provides utility functions for cryptographic operations
// // in the BBS signature scheme. It includes functions for generating random scalars,
// // hashing to scalars, and serializing elements of the elliptic curve groups.
// // The package uses the BLS12-381 elliptic curve for cryptographic operations.
package utils

import (
    "crypto/rand"
    "math/big"
	"crypto/sha256"
    "errors"

    e "github.com/cloudflare/circl/ecc/bls12381"
)

// RandomScalar generates a random scalar in Z_p* (the field of scalars modulo the curve order).
func RandomScalar() (e.Scalar, error) {
    order := OrderAsBigInt()
    bigIntScalar, err := rand.Int(rand.Reader, order)
    if err != nil {
        return e.Scalar{}, errors.New("failed to generate random scalar")
    }

    if bigIntScalar.Sign() == 0 { // Ensure it's nonzero
        return RandomScalar()
    }

    // Convert to a scalar
    var scalar e.Scalar
    scalar.SetBytes(bigIntScalar.Bytes())
    return scalar, nil
}

// RandomG1Element generates a random element in the elliptic curve group G1.
func RandomG1Element() (e.G1, error) {
    var h e.G1
    randomBytes := make([]byte, 48)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return e.G1{}, errors.New("failed to generate random input for hashing to G1")
    }

    // Hash the random bytes to the curve using a domain separation tag
    h.Hash(randomBytes, []byte("domain-separation-tag"))
    return h, nil
}

// OrderAsBigInt returns the order of the elliptic curve as a big.Int.
func OrderAsBigInt() *big.Int {
    return new(big.Int).SetBytes(e.Order())
}

// HashToScalar hashes a series of byte slices into a scalar in Z_p*.
func HashToScalar(inputs ...[]byte) (e.Scalar, error) {
    hash := sha256.New()

    // Write each input to the hash
    for _, input := range inputs {
        _, err := hash.Write(input)
        if err != nil {
            return e.Scalar{}, errors.New("failed to hash input")
        }
    }
    digest := hash.Sum(nil)

    // Convert hash output into a scalar
    var scalar e.Scalar
    order := new(big.Int).SetBytes(e.Order())
    bigIntScalar := new(big.Int).SetBytes(digest)
    bigIntScalar.Mod(bigIntScalar, order) // Ensure it is in Z_p
    scalar.SetBytes(bigIntScalar.Bytes())
    
    return scalar, nil
}

// Serialize G1 element to bytes
func SerializeG1(g *e.G1) []byte {
    return g.Bytes()
}

// Serialize Gt element to bytes
func SerializeGt(g *e.Gt) []byte {
	data, _ := g.MarshalBinary()
	return data
}

// Serialize string to bytes
func SerializeString(s string) []byte {
	return []byte(s)
}