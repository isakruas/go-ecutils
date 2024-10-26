// Package eck provides a simple implementation of Elliptic Curve Cryptography encoding and decoding.
// It defines two main functions - Encode() and Decode().
// The Encode function maps a short message to a point on an elliptic curve.
// The Decode function takes an elliptic curve point and an integer, and retrieves the original message.
// Reference: https://doi.org/10.1090/S0025-5718-1987-0866109-5.
package eck

import (
	"fmt"
	"math/big"

	"github.com/isakruas/go-ecutils/internal/ec"
)

// ECK structure holding an elliptic curve
type ECK struct {
	Curve        *ec.EC
	EncodingType string
}

// Encode function takes a string message and encodes it into a point on the elliptic curve
func (eck *ECK) Encode(message string) (*ec.Point, *big.Int) {

	if eck.EncodingType == "" {
		eck.EncodingType = "unicode" // Default value
	}

	exp := big.NewInt(0)
	maxBytes := 32
	if eck.EncodingType == "unicode" {
		// Unicode encoding
		exp.SetInt64(16)
	} else if eck.EncodingType == "ascii" {
		// ASCII encoding
		exp.SetInt64(8)
		maxBytes = 64
	} else {
		panic(fmt.Sprintf("Unsupported encoding type: %s", eck.EncodingType))
	}

	if len(message) < maxBytes {
		maxBytes = len(message)
	}
	m := message[:maxBytes]
	b := new(big.Int).Exp(big.NewInt(2), exp, nil) // b = 2^exp
	n := len(m)

	mInt := big.NewInt(0)
	for k := 0; k < n; k++ {
		c := new(big.Int).SetUint64(uint64(m[k]))
		e := new(big.Int).Exp(b, big.NewInt(int64(k)), nil)
		t := new(big.Int).Mul(c, e)
		mInt.Add(mInt, t)
	}

	// Calculate d
	p := eck.Curve.P
	// d := new(big.Int).Div(p, mInt)
	// if d.Cmp(big.NewInt(100)) > 0 {
	// 	d.Set(big.NewInt(100))
	// }
	d := big.NewInt(100)

	j := big.NewInt(0)

	var x, s, y *big.Int

	// Find an x coordinate that, when substituted into the elliptic curve equation, gives a square (s = u^2 mod p)
	for {
		x = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(d, mInt), j), p)
		s = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), nil), new(big.Int).Mul(eck.Curve.A, x)), eck.Curve.B), p)
		u := new(big.Int).Exp(s, new(big.Int).Div(new(big.Int).Add(p, big.NewInt(1)), big.NewInt(2)), p)
		if s.Cmp(u) == 0 {
			y = new(big.Int).Exp(s, new(big.Int).Div(new(big.Int).Add(p, big.NewInt(1)), big.NewInt(4)), p)
			break
		}
		j.Add(j, big.NewInt(1))
	}

	// Return the elliptic curve point and the error length
	return &ec.Point{Px: x, Py: y}, j
}

// Decode function takes an elliptic curve point E and the integer j and decodes it to the original message
func (eck *ECK) Decode(E *ec.Point, j *big.Int) string {
	if eck.EncodingType == "" {
		eck.EncodingType = "unicode" // Default value
	}

	exp := big.NewInt(0)

	if eck.EncodingType == "unicode" {
		// Unicode encoding
		exp.SetInt64(16)
	} else if eck.EncodingType == "ascii" {
		// ASCII encoding
		exp.SetInt64(8)
	} else {
		panic(fmt.Sprintf("Unsupported encoding type: %s", eck.EncodingType))
	}

	b := new(big.Int).Exp(big.NewInt(2), exp, nil) // b = 2^exp

	d := big.NewInt(100)
	lst := []rune{}

	x := new(big.Int).Sub(E.Px, j)
	m := new(big.Int).Div(x, d)
	zero := big.NewInt(0)

	// Convert big integer m back to the original message
	for m.Cmp(zero) != 0 {
		r := new(big.Int).Mod(m, b)
		lst = append(lst, rune(r.Int64()))
		m.Div(m, b)
	}

	return string(lst)
}
