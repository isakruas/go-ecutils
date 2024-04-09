// Package ecdh implements an Elliptic Curve Diffie Hellman (ECDH) protocol,
// which allows two parties, each having an elliptic curve public-private key pair,
// to establish a shared secret over an insecure channel. This shared secret may be
// directly used as a key, or to derive another key. The key, or the derived key,
// can then be used to encrypt subsequent communications using a symmetric key cipher.
// Reference: https://en.wikipedia.org/wiki/Elliptic-curve_Diffie-Hellman
package ecdh

import (
	"ecutils/internal/ec"
	"math/big"
)

// ECDH represents an Elliptic Curve Diffie Hellman entity with a curve and a private key
type ECDH struct {
	Curve      *ec.EC   // The elliptic curve
	PrivateKey *big.Int // The private key for ECDH
}

// PublicKey returns the public key of the ECDH entity,
// The public key is obtained by performing the trapdoor function to G (base point) with the private key
func (ecdh *ECDH) PublicKey() ec.Point {
	return ecdh.Curve.Trapdoor(
		&ec.Point{
			Px: ecdh.Curve.Gx, // x-coordinate of base point
			Py: ecdh.Curve.Gy, // y-coordinate of base point
		},
		new(big.Int).Set(ecdh.PrivateKey), // The private key
	)
}

// ToShare performs the ECDH shared secret process with a public key from another ECDH entity.
// The shared secret is obtained by performing the trapdoor function to the public key with our private key.
func (ecdh *ECDH) ToShare(PublicKey *ec.Point) ec.Point {
	return ecdh.Curve.Trapdoor(
		&ec.Point{
			Px: PublicKey.Px, // x-coordinate of public key
			Py: PublicKey.Py, // y-coordinate of public key
		},
		new(big.Int).Set(ecdh.PrivateKey), // The private key
	)
}
