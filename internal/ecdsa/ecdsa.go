// Package ecdsa provides an implementation of the Elliptic Curve Digital Signature Algorithm.
// It provides methods to generate public and private keys, create digital signatures, and verify them.
// This package relies on the supporting "ecutils/ec" package for operations on elliptic curves.
// Note: This package does not handle message hashing, only raw message values. It is up to the user to
// preprocess the message as necessary before using the signing and verification methods.
// Reference: https://pt.wikipedia.org/wiki/ECDSA
package ecdsa

import (
	"ecutils/internal/ec"
	"math/big"
	"math/rand"
	"time"
)

// ECDSA structure
type ECDSA struct {
	Curve      *ec.EC   // Elliptic curve
	PrivateKey *big.Int // Private key
}

// PublicKey method generates the public key corresponding to
// the given private key of ecdsa instance.
func (ecdsa *ECDSA) PublicKey() ec.Point {
	// Generates public key using trapdoor function applied on base point with private key
	return ecdsa.Curve.Trapdoor(
		&ec.Point{
			Px: ecdsa.Curve.Gx,
			Py: ecdsa.Curve.Gy,
		},
		new(big.Int).Set(ecdsa.PrivateKey),
	)
}

// Signature method generates the ECDSA signature for a given message.
// The signature consists of two integer values 'r' and 's'.
func (ecdsa *ECDSA) Signature(message *big.Int) (*big.Int, *big.Int) {

	r := new(big.Int)
	s := new(big.Int)

	privateKey := new(big.Int).Set(ecdsa.PrivateKey)

	// Generate r, s until both are non-zero
	for r.Cmp(big.NewInt(0)) == 0 || s.Cmp(big.NewInt(0)) == 0 {
		// Random value k
		k := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), new(big.Int).Sub(ecdsa.Curve.N, big.NewInt(1)))
		k.Add(k, big.NewInt(1))

		// point P = k*G
		P := ecdsa.Curve.Trapdoor(
			&ec.Point{
				Px: ecdsa.Curve.Gx,
				Py: ecdsa.Curve.Gy,
			}, k,
		)
		// r = Px mod n
		r.Mod(P.Px, ecdsa.Curve.N)
		// s = (message + r*privateKey) / k mod n
		s.Mod(new(big.Int).Mul(new(big.Int).Add(message, new(big.Int).Mul(r, privateKey)), new(big.Int).ModInverse(k, ecdsa.Curve.N)), ecdsa.Curve.N)
	}

	return r, s
}

// VerifySignature method verifies the ECDSA signature for a given message
// and Public Key. It returns true if the signature is valid, false otherwise.
func (ecdsa *ECDSA) VerifySignature(message *big.Int, r *big.Int, s *big.Int, publicKey *ec.Point) bool {

	// Calculate needed points
	P := ecdsa.Curve.Trapdoor(
		&ec.Point{
			Px: ecdsa.Curve.Gx,
			Py: ecdsa.Curve.Gy,
		}, new(big.Int).Mod(new(big.Int).Mul(message, new(big.Int).ModInverse(s, ecdsa.Curve.N)), ecdsa.Curve.N),
	)

	Q := ecdsa.Curve.Trapdoor(
		&ec.Point{
			Px: publicKey.Px,
			Py: publicKey.Py,
		},
		new(big.Int).Mod(new(big.Int).Mul(r, new(big.Int).ModInverse(s, ecdsa.Curve.N)), ecdsa.Curve.N),
	)

	// Point R =  P + Q
	R := ecdsa.Curve.Dot(P, Q)

	// v = Px mod n
	v := new(big.Int).Mod(R.Px, ecdsa.Curve.N)

	// If r equals to v then the signature is valid
	if r.Cmp(v) == 0 {
		return true
	}

	return false
}
