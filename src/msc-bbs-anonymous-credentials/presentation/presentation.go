package presentation

import (
	"fmt"
	"github.com/aniagut/msc-bbs-anonymous-credentials/models"
	"github.com/aniagut/msc-bbs-anonymous-credentials/utils"
	"log"
	e "github.com/cloudflare/circl/ecc/bls12381"
)

// Present presents attributes and generates a proof of knowledge of the valid credential for the given attributes (both revealed and non-revealed).
// It uses the BBS+ signature scheme to create a zero-knowledge proof of knowledge of the valid credential for the given attributes.
// The function takes the attributes, credential, revealed attributes, and public parameters as input.
// It returns a proof of knowledge of the valid credential for the given attributes.
// Arguments:
//   - attributes: The list of attributes to be presented.
//   - credential: The BBS+ signature representing the credential.
//   - revealed: The list of indexes for revealed attributes.
//   - publicParams: The public parameters of the system.
//   - nonce: A random nonce used for the proof.
// Returns:
//   - SignatureProof: The generated proof of knowledge of the valid credential for the given attributes.
//   - error: An error if the presentation process fails.
func Presentation(attributes []string, credential models.Signature, revealed []int, publicParams models.PublicParameters, nonce []byte) (models.SignatureProof, error){
	// Step 1: Compute the revealed and hidden attributes
	revealedAttributes, hiddenAttributes, err := ComputeRevealedAndHiddenAttributes(attributes, revealed)
	if err != nil {
		log.Printf("Error computing revealed attributes: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 2: Compute h values h₁[i] ← g1^m[i] for revealed and hidden attributes a[i]
	revealedH, hiddenH, err := utils.ComputeRevealedAndHiddenH(publicParams.H1, revealed)
	if err != nil {
		log.Printf("Error computing revealed and hidden h values: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 3: Compute the commitment for revealed attributes C_rev ← g1 * ∏_i h₁[i]^a[i]
	// where m[i] is the i-th revealed attribute.
	C_rev, err := utils.ComputeCommitment(revealedAttributes, revealedH, publicParams.G1)
	if err != nil {
		log.Printf("Error computing commitment: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 4: Select random r ← Z_p* and ensure
	r, err := utils.RandomScalar()
	if err != nil {
		log.Printf("Error generating random scalar r: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 5: Compute the signature component A_prim ← A^r
	A_prim := new(e.G1)
	A_prim.ScalarMult(&r, credential.A)

	// Step 6: Compute the signature component B_prim ← C_rev^r * ∏_i h₁[i]^a[i] * A_prim^(-e) for i ∈ hidden
	C_rev_exp := new(e.G1)
	C_rev_exp.ScalarMult(&r, C_rev)
	
	// Convert hidden attributes to scalars
	hiddenHScalars := make([]e.Scalar, len(hiddenAttributes))
	for i := 0; i < len(hiddenAttributes); i++ {
		hiddenHScalars[i].SetBytes(utils.SerializeString(hiddenAttributes[i]))
	}
	h1ExpHidden , err:= utils.ComputeH1Exp(hiddenH, hiddenHScalars)
	if err != nil {
		log.Printf("Error computing hidden h1 exponent: %v", err)
		return models.SignatureProof{}, err
	}

	e_inv := new(e.Scalar)
	e_inv.Inv(credential.E)

	A_prim_exp := new(e.G1)
	A_prim_exp.ScalarMult(e_inv, A_prim)

	B_prim := new(e.G1)
	B_prim.Add(C_rev_exp, h1ExpHidden)
	B_prim.Add(B_prim, A_prim_exp)

	// Step 7: Compute random scalars v_r, {v_j} for j ∈ hidden and v_e
	v_r, err := utils.RandomScalar()
	if err != nil {
		log.Printf("Error generating random scalar v_r: %v", err)
		return models.SignatureProof{}, err
	}
	v_e, err := utils.RandomScalar()
	if err != nil {
		log.Printf("Error generating random scalar v_e: %v", err)
		return models.SignatureProof{}, err
	}
	v_j := make([]e.Scalar, len(hiddenAttributes))
	for i := 0; i < len(hiddenAttributes); i++ {
		v_j[i], err = utils.RandomScalar()
		if err != nil {
			log.Printf("Error generating random scalar v_j[%d]: %v", i, err)
			return models.SignatureProof{}, err
		}
	}

	// Step 8: Compute U ← C_rev^v_r * ∏_j h₁[j]^v_j * A_prim^v_e for j ∈ hidden
	C_rev_exp_v_r := new(e.G1)
	C_rev_exp_v_r.ScalarMult(&v_r, C_rev)
	h1Exp_v_j, err := utils.ComputeH1Exp(hiddenH, v_j)
	if err != nil {
		log.Printf("Error computing hidden h1 exponent: %v", err)
		return models.SignatureProof{}, err
	}
	A_prim_exp_v_e := new(e.G1)
	A_prim_exp_v_e.ScalarMult(&v_e, A_prim)
	U := new(e.G1)
	U.Add(C_rev_exp_v_r, h1Exp_v_j)
	U.Add(U, A_prim_exp_v_e)

	// Step 9: Compute the challenge ch ← H(nonce, U, A_prim, B_prim, {a_i}) for i ∈ revealed
	ch, err := utils.ComputeChallenge(nonce, U, A_prim, B_prim, revealedAttributes)
	if err != nil {
		log.Printf("Error computing challenge: %v", err)
		return models.SignatureProof{}, err
	}

	// Step 10: Blind v_r, {v_j} for j ∈ hidden and v_e
	// z_r ← v_r + ch * e
	z_r := new(e.Scalar)
	z_r.Mul(&ch, credential.E)
	z_r.Add(z_r, &v_r)
	// z_j <- v_j + ch * r *  a_j for j ∈ hidden
	z_j := make([]e.Scalar, len(hiddenAttributes))
	for i := 0; i < len(hiddenAttributes); i++ {
		z_j[i].Mul(&ch, &r)
		aScalar := new(e.Scalar)
        aScalar.SetBytes(utils.SerializeString(hiddenAttributes[i]))
		z_j[i].Mul(&z_j[i], aScalar)
		z_j[i].Add(&z_j[i], &v_j[i])
	}
	// z_e <- v_e - ch * e
	z_e := new(e.Scalar)
	z_e.Mul(&ch, credential.E)
	z_e.Neg()
	z_e.Add(z_e, &v_e)

	// Step 11: Return the proof of knowledge of the valid credential for the given attributes
	return models.SignatureProof{
		A_prim: A_prim,
		B_prim: B_prim,
		Ch:     &ch,
		Z_r:    z_r,
		Z_i:    z_j,
		Z_e:    z_e,
	}, nil
}

// ComputeRevealedAndHiddenAttributes computes the lists of hidden and revealed attributes based on the given indexes.
func ComputeRevealedAndHiddenAttributes(attributes []string, revealed []int) ([]string, []string, error) {
	if len(revealed) == 0 {
		return nil, nil, fmt.Errorf("no revealed attributes provided")
	}
	if len(revealed) > len(attributes) {
		return nil, nil, fmt.Errorf("revealed attributes exceed total attributes")
	}
	// Check if revealed indexes are valid
	for _, index := range revealed {
		if index < 0 || index >= len(attributes) {
			return nil, nil, fmt.Errorf("revealed index %d out of bounds", index)
		}
	}
	
	// Create a map for quick lookup of revealed indexes
    revealedMap := make(map[int]bool, len(revealed))
    for _, index := range revealed {
        revealedMap[index] = true
    }

    // Create slices for revealed and hidden attributes
    revealedAttributes := make([]string, 0, len(revealed))
    hiddenAttributes := make([]string, 0, len(attributes)-len(revealed))

    for i, attr := range attributes {
        if revealedMap[i] {
            revealedAttributes = append(revealedAttributes, attr)
        } else {
            hiddenAttributes = append(hiddenAttributes, attr)
        }
    }

    return revealedAttributes, hiddenAttributes, nil
}