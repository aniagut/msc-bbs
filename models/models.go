// Package models provides the data structures and types used in the BBS+ signature scheme.
// // It includes the public key, secret manager key, user keys, and the signature structure.
package models

import (
    e "github.com/cloudflare/circl/ecc/bls12381"
)

// PublicKey represents the public key of the system.
// It contains the following elements:
// - G1, G2: Generators of the elliptic curve groups G1 and G2.
// - H, U, V, W: Additional public parameters used in the signature scheme.
type PublicKey struct {
    G1      *e.G1
    G2      *e.G2
    H       *e.G1
    U       *e.G1
    V       *e.G1
    W       *e.G2
}

// SecretManagerKey represents the secret key managed by the system.
// It contains the following elements:
// - Epsilon1, Epsilon2: Scalars used as part of the secret key.
type SecretManagerKey struct {
    Epsilon1 e.Scalar
    Epsilon2 e.Scalar
}

// Signature represents a BBS signature.
// It contains the following elements:
// - T1, T2, T3: Commitment values computed during the signature generation.
// - C: The challenge scalar derived from the hash of the message and commitments.
// - S_alpha, S_beta, S_x, S_delta1, S_delta2: Response values used in the signature proof.
type Signature struct {
    T1 *e.G1
    T2 *e.G1
    T3 *e.G1
    C e.Scalar
    S_alpha *e.Scalar
    S_beta *e.Scalar
    S_x *e.Scalar
    S_delta1 *e.Scalar
    S_delta2 *e.Scalar
}

// User represents a users' private keys in the system.
type User struct {
    A *e.G1
    X e.Scalar
}

// KeyGenResult represents the result of the key generation process.
// It contains the following elements:
// - PublicKey: The public key of the system.
// - SecretManagerKey: The secret key managed by the system.
// - Users: A list of users with their respective private keys.
type KeyGenResult struct {
    PublicKey       PublicKey
    SecretManagerKey SecretManagerKey
    Users           []User
}
