package models

import (
    e "github.com/cloudflare/circl/ecc/bls12381"
)

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

type User struct {
    A *e.G1
    X e.Scalar
}