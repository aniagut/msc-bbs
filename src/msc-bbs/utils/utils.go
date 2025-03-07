package utils

import (
    "crypto/rand"
    "math/big"
	"crypto/sha256"
    e "github.com/cloudflare/circl/ecc/bls12381"
)

// randomScalar generates a random scalar in Zp*
func RandomScalar() e.Scalar {
    order := OrderAsBigInt()
    bigIntScalar, _ := rand.Int(rand.Reader, order)
    if bigIntScalar.Sign() == 0 { // Ensure it's nonzero
        return RandomScalar()
    }
    var scalar e.Scalar
    scalar.SetBytes(bigIntScalar.Bytes())
    return scalar
}

// randomG1Element generates a random element in G1 by has to curve method
func RandomG1Element() e.G1 {
    var h e.G1
    randomBytes := make([]byte, 32)
    _, err := rand.Read(randomBytes)
    if err != nil {
        panic("Failed to generate random input for hashing to G1")
    }
    
    h.Hash(randomBytes, []byte("domain-separation-tag"))
    return h
}

// OrderAsBigInt returns the order of the curve as a big.Int
func OrderAsBigInt() *big.Int {
    return new(big.Int).SetBytes(e.Order())
}

func HashToScalar(inputs ...[]byte) e.Scalar {
    hash := sha256.New()
    for _, input := range inputs {
        hash.Write(input)
    }
    digest := hash.Sum(nil)

    // Convert hash output into a scalar
    var scalar e.Scalar
    order := new(big.Int).SetBytes(e.Order())
    bigIntScalar := new(big.Int).SetBytes(digest)
    bigIntScalar.Mod(bigIntScalar, order) // Ensure it is in Z_p
    scalar.SetBytes(bigIntScalar.Bytes())
    
    return scalar
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