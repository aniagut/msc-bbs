package main

import (
	"fmt"
	"crypto/rand"
	"math/big"
	"errors"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

type KeyGenResult struct {
	SigningKey       SigningKey
	VerificationKey  VerificationKey
	PublicParameters PublicParameters
}

type SigningKey struct {
	X *e.Scalar
}

type VerificationKey struct {
	X2 *e.G2
}

type PublicParameters struct {
	G1 *e.G1
	G2 *e.G2
	H1 []e.G1
}

type Signature struct {
	A *e.G1
	e *e.Scalar
}
	

// KeyGen generates the key material for the BBS++ signature scheme.
// 
// Parameters:
//   - l - length of the messages vector
//
// Returns:
//   - KeyGenResult: A struct containing the keys for signing and verifying messages.
//   - error: An error if key generation fails.
func KeyGen(l int) (KeyGenResult, error) {
	
	// 1. Select Generators g1 ∈ G1 and g2 ∈ G2
	g1 := e.G1Generator()
	g2 := e.G2Generator()

	// 2. Select random h_1[1..l] ← independent generators of G1
	h1, err:= GenerateLRandomG1Elements(l)
	if err != nil {
		return KeyGenResult{}, err
	}

	// 3. Select random x ∈ Zp*
	x, err := RandomScalar()
	if err != nil {
		return KeyGenResult{}, err
	}

	// 4. Compute verification key vk = X₂ ← g₂^x
	X2 := new(e.G2)
	X2.ScalarMult(&x, g2)

	// Return the result
	return KeyGenResult{
		SigningKey: SigningKey{
			X: &x,
		},
		VerificationKey: VerificationKey{
			X2: X2,
		},
		PublicParameters: PublicParameters{
			G1: g1,
			G2: g2,
			H1: h1,
		},
	}, nil
}

// Sign generates a BBS++ signature for a given message.
//
// Parameters:
//   - publicParams: The public key of the system.
//   - signingKey: The key used for signing the message.
//   - M: The message to be signed.
//
// Returns:
//   - Signature: The generated signature.
//   - error: An error if the signing process fails.
func Sign(publicParams PublicParameters, signingKey SigningKey, M []string) (Signature, error) {
	// Step 1: Compute commitment C ← g1 * ∏_i h₁[i]^m[i]
	C, err := ComputeCommitment(M, publicParams.H1, publicParams.G1)
    if err != nil {
        return Signature{}, err
    }

	// Step 2: Set random elem ← Z_p* and ensure x + e ≠ 0
	elem := new(e.Scalar)
	for {
		randomScalar, err := RandomScalar()
		if err != nil {
			return Signature{}, errors.New("failed to generate random scalar e")
		}

		// Check if x + e ≠ 0
		elem.Add(signingKey.X, &randomScalar)
		if elem.IsZero() == 0 {
			break
		}
	}

	fmt.Println("Random scalar e:", elem)

	// Step 3: Compute signature component A <- C^{1 / (x + e)} ∈ G_1
	A := computeA(signingKey.X, elem, C)

	// Step 4: Return the signature σ = (A, e)
	return Signature{
		A: A,
		e: elem,
	}, nil
}

// Verify checks the validity of a BBS++ signature.
//
// Parameters:
//   - publicParams: The public parameters of the system.
//   - verificationKey: The verification key of the system.
//   - M: The message to be verified.
//   - signature: The signature to be verified.
//
// Returns:
//   - boolean: True if the signature is valid, false otherwise.
//   - error: An error if the verification process fails.
func Verify(publicParams PublicParameters, verificationKey VerificationKey, M []string, signature Signature) (bool, error) {
	// Step 1: Compute commitment C ← g1 * ∏_i h₁[i]^m[i]
	C, err := ComputeCommitment(M, publicParams.H1, publicParams.G1)
	if err != nil {
		return false, err
	}

	// Step 2: Check pairing e(A, g₂^e · vk) ?= e(C, g₂)
	// If equal, return true
	g_2_e := new(e.G2)
	g_2_e.ScalarMult(signature.e, publicParams.G2)
	g_2_e.Add(g_2_e, verificationKey.X2)

	e1 := new(e.Gt)
	e1 = e.Pair(signature.A, g_2_e)
	fmt.Println("e1:", e1)
	e2 := new(e.Gt)
	e2 = e.Pair(C, publicParams.G2)
	fmt.Println("e2:", e2)
	if e1.IsEqual(e2) == false {
		return false, nil
	}
	return true, nil
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


func GenerateLRandomG1Elements(l int) ([]e.G1, error) {
	elements := make([]e.G1, l)
	for i := 0; i < l; i++ {
		element, err := RandomG1Element()
		if err != nil {
			return nil, err
		}
		elements[i] = element
	}
	return elements, nil
}

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

// OrderAsBigInt returns the order of the elliptic curve as a big.Int.
func OrderAsBigInt() *big.Int {
    return new(big.Int).SetBytes(e.Order())
}

// Serialize string to bytes
func SerializeString(s string) []byte {
	return []byte(s)
}

// ComputeCommitment computes the commitment C for a given message M.
func ComputeCommitment(M []string, h1 []e.G1, g1 *e.G1) (*e.G1, error) {
	// Ensure the message vector length matches the length of h1
    if len(M) != len(h1) {
        return nil, errors.New("message vector length does not match h1 length")
    }

	// Initialize the commitment C with g1
	C := new(e.G1)
	*C = *g1

	for i, message := range M {
		// Convert message to a scalar
		mScalar := new(e.Scalar)
		mScalar.SetBytes(SerializeString(message))

		// Compute h1[i]^m[i]
        h1Exp := new(e.G1)
        h1Exp.ScalarMult(mScalar, &h1[i])

        // Multiply the result into the commitment
        C.Add(C, h1Exp)
	}

	return C, nil
}

func computeA(x *e.Scalar, elem *e.Scalar, C *e.G1) *e.G1 {
	// Compute signature component A <- C^{1 / (x + e)} ∈ G_1
	x_plus_e := new(e.Scalar)
	x_plus_e.Add(x, elem)

	// Compute the inverse of (x + e)
	x_plus_e.Inv(x_plus_e)

	// Compute A = C^{1 / (x + e)}
	A := new(e.G1)
	A.ScalarMult(x_plus_e, C)
	return A
}

func main() {
	// Example usage of KeyGen
	l := 5 // Length of the messages vector
	result, err := KeyGen(l)
	if err != nil {
		fmt.Println("Error generating keys:", err)
		return
	}

	fmt.Println("Signing Key:", result.SigningKey.X)
	fmt.Println("Verification Key:", result.VerificationKey.X2)
	fmt.Println("Generated keys successfully.")

	// Example usage of Sign
	M := []string{"message1", "message2", "message3", "message4", "message5"}
	signature, err := Sign(result.PublicParameters, result.SigningKey, M)
	if err != nil {
		fmt.Println("Error signing message:", err)
		return
	}
	fmt.Println("Signature A:", signature.A)
	fmt.Println("Signature e:", signature.e)
	fmt.Println("Signature generated successfully.")

	// Example usage of Verify
	M1 := []string{"message1", "message2", "message3", "message4", "message5"}
	isValid, err := Verify(result.PublicParameters, result.VerificationKey, M1, signature)
	if err != nil {
		fmt.Println("Error verifying signature:", err)
		return
	}
	fmt.Println("Is the signature valid?", isValid)
}

