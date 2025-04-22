package models

import (
    e "github.com/cloudflare/circl/ecc/bls12381"
)

// SetupResult represents the result of the setup process.
// It contains the following elements:
// - PublicParameters: The public parameters of the system.
// - PublicKey: The public key of the system.
// - SecretKey: The secret key of the system.
type SetupResult struct {
    PublicParameters PublicParameters
	PublicKey        PublicKey
	SecretKey	     SecretKey
}

// PublicParameters represents the public parameters of the system.
// It contains the following elements:
// - G1, G2: Generators of the elliptic curve groups G1 and G2.
// - H1: A list of independent generators of G1.
type PublicParameters struct {
	G1 *e.G1
	G2 *e.G2
	H1 []e.G1
}

// PublicKey represents the public key of the system.
// It contains the following elements:
// - X2: The verification key computed as g2^x.
type PublicKey struct {
	X2 *e.G2
}

// SecretKey represents the secret key of the system.
// It contains the following elements:
// - X: A random scalar used in the signing process.
type SecretKey struct {
	X *e.Scalar
}

// Signature represents a BBS++ signature.
// It contains the following elements:
// - A: The first component of the signature, computed as C^{1 / (x + e)} ∈ G1.
// - E: The random scalar used in the signing process.
type Signature struct {
	A *e.G1
	E *e.Scalar
}