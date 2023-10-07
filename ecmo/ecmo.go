// Package ecmo implements the Massey–Omura elliptic curve protocol for secure
// encryption and decryption of messages. This protocol is a three-pass protocol
// which involves entities A and B exchanging messages three times in order to ensure
// a secure connection. The advantage of this protocol is that it does not require
// the participants to share secret information prior to initiation. Instead, each
// participant has a pair of keys (public and private), and these keys are used to
// encrypt and decrypt messages. The private key is kept secret, while the public key
// is shared with others. The security of this protocol relies on the difficulty of
// solving the elliptic curve discrete logarithm problem.
// Reference: https://en.wikipedia.org/wiki/Three-pass_protocol
package ecmo

import (
	"ecutils/ec"
	"ecutils/ecdh"
	"ecutils/ecdsa"
	"ecutils/eck"
	"math/big"
)

// ECMO represents the Massey–Omura elliptic curve protocol.
// PrivateKey is the private key for the entity using the protocol.
type ECMO struct {
	Curve           *ec.EC
	PrivateKey      *big.Int
	ECKEncodingType string
}

// PublicKey returns the corresponding public key of the private key.
func (ecmo *ECMO) PublicKey() ec.Point {
	return ecmo.Curve.Trapdoor(
		&ec.Point{
			Px: ecmo.Curve.Gx,
			Py: ecmo.Curve.Gy,
		},
		new(big.Int).Set(ecmo.PrivateKey),
	)
}

// Encrypt encrypts a message using recipient's public key.
// Returns encrypted message, encoded message, signature pair (r, s) and a temporary used key.
func (ecmo *ECMO) Encrypt(message string, to *ec.Point) (*ec.Point, *big.Int, *big.Int, *big.Int) {
	eck := eck.ECK{
		Curve:        ecmo.Curve,
		EncodingType: ecmo.ECKEncodingType,
	}
	ecdh := ecdh.ECDH{
		Curve:      ecmo.Curve,
		PrivateKey: new(big.Int).Set(ecmo.PrivateKey),
	}
	ecdsa := ecdsa.ECDSA{
		Curve:      ecmo.Curve,
		PrivateKey: new(big.Int).Set(ecmo.PrivateKey),
	}
	P, j := eck.Encode(message)
	Q := ecmo.Curve.Trapdoor(P, ecdh.ToShare(to).Px)
	r, s := ecdsa.Signature(Q.Px)
	return &Q, j, r, s
}

// Decrypt decodes the encoded message using private key.
// Panics if signatures do not match.
// Returns the decoded message after the verification of the signatures.
func (ecmo *ECMO) Decrypt(Q *ec.Point, j *big.Int, r *big.Int, s *big.Int, got *ec.Point) string {
	eck := eck.ECK{
		Curve:        ecmo.Curve,
		EncodingType: ecmo.ECKEncodingType,
	}
	ecdh := ecdh.ECDH{
		Curve:      ecmo.Curve,
		PrivateKey: new(big.Int).Set(ecmo.PrivateKey),
	}
	ecdsa := ecdsa.ECDSA{
		Curve:      ecmo.Curve,
		PrivateKey: ecmo.PrivateKey,
	}
	valid := ecdsa.VerifySignature(Q.Px, r, s, got)
	if !valid {
		panic("Invalid signature")
	}

	P := ecmo.Curve.Trapdoor(Q, new(big.Int).ModInverse(ecdh.ToShare(got).Px, ecdsa.Curve.N))

	return eck.Decode(&P, j)
}
