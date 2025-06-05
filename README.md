# msc-bbs

## Overview
This project implements a short group signatures scheme, a cryptographic protocol that enables anonymous authentication while maintaining accountability.

Paper: https://eprint.iacr.org/2004/174.pdf

## Features

- **Key Generation**: Efficient concurrent and sequential key generation for group members.
- **Signing**: BBS signature scheme implementation using the BLS12-381 elliptic curve.
- **Verification**: Signature verification and signer identification.
- **Open/Trace**: Ability to open a signature and identify the signer using a secret manager key.
- **Benchmarks**: Experimental scripts for measuring performance of key generation, signing, verification, and pairing operations.

## Installation

```bash
go get github.com/aniagut/msc-bbs@latest
```

## Usage

Import the package(s) you need in your Go code:

```go
import (
    "github.com/aniagut/msc-bbs/keygen"
    "github.com/aniagut/msc-bbs/sign"
    "github.com/aniagut/msc-bbs/verify"
    "github.com/aniagut/msc-bbs/open"
)
```

### Example: Key Generation

```go
result, err := keygen.KeyGen(10) // Generate keys for 10 users
if err != nil {
    // handle error
}
```

### Example: Signing

```go
signature, err := sign.Sign(result.PublicKey, result.Users[0], "hello world")
if err != nil {
    // handle error
}
```

### Example: Verification

```go
valid, err := verify.Verify(result.PublicKey, "hello world", signature)
if err != nil {
    // handle error
}
if valid {
    // signature is valid
}
```

### Example: Open/Trace

```go
signerIndex, err := open.Open(result.PublicKey, result.SecretManagerKey, "hello world", signature, result.Users)
if err != nil {
    // handle error
}
// signerIndex is the index of the user who signed
```

## Experiments

Performance experiments are available in the `experiments/` directory.  
Results are saved in `experiments/results/`.

## Documentation

- [GoDoc on pkg.go.dev](https://pkg.go.dev/github.com/aniagut/msc-bbs)

## License

MIT License

---