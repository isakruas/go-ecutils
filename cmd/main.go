package main

import (
	pkg_ec "ecutils/internal/ec"
	pkg_ecdh "ecutils/internal/ecdh"
	pkg_ecdsa "ecutils/internal/ecdsa"
	pkg_eck "ecutils/internal/eck"
	pkg_ecmo "ecutils/internal/ecmo"

	"flag"
	"fmt"
	"math/big"
)

// GOOS represents the operating system on which the program is running.
var GOOS string

// GOARCH represents the architecture of the operating system on which the program is running.
var GOARCH string

// CODEVERSION represents the version of the code.
var CODEVERSION string

// CODEBUILDDATE represents the date when the program was built.
var CODEBUILDDATE string

// CODEBUILDREVISION represents the revision of the code build.
var CODEBUILDREVISION string

func main() {

	// Defer a function to recover from a panic and handle errors gracefully.
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("An error occurred:", r)
		}
	}()

	// Program
	var info, license bool
	flag.BoolVar(&info, "info", false, "Display program compilation and version information")
	flag.BoolVar(&license, "license", false, "Display program license information")

	// EC
	var ecGet string
	var ec, ecDot, ecTrapdoor, ecDefine bool
	var ecDotPx, ecDotPy, ecDotQx, ecDotQy string
	var ecTrapdoorGx, ecTrapdoorGy, ecTrapdoorK string
	var ecDefineP, ecDefineA, ecDefineB, ecDefineGx, ecDefineGy, ecDefineN, ecDefineH string

	flag.BoolVar(&ec, "ec", false, "Enables operations on Elliptic Curves.")
	flag.StringVar(&ecGet, "ec-get", "secp192k1", "Identifies Elliptic Curve for operations. Supported curves: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.")
	flag.BoolVar(&ecDefine, "ec-define", false, "Enables the definition of a new Elliptic Curve.")
	flag.StringVar(&ecDefineP, "ec-define-p", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", "Defines 'p' prime modulus of the Elliptic Curve in hex format.")
	flag.StringVar(&ecDefineA, "ec-define-a", "0", "Defines 'a' coefficient of the Elliptic Curve in hex format.")
	flag.StringVar(&ecDefineB, "ec-define-b", "3", "Defines 'b' coefficient of the Elliptic Curve in hex format.")
	flag.StringVar(&ecDefineGx, "ec-define-gx", "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", "Defines x-coordinate of base point 'G' on the Elliptic Curve in hex format.")
	flag.StringVar(&ecDefineGy, "ec-define-gy", "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", "Defines y-coordinate of base point 'G' on the Elliptic Curve in hex format.")
	flag.StringVar(&ecDefineN, "ec-define-n", "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", "Defines order 'n' of base point 'G' on the Elliptic Curve in hex format.")
	flag.StringVar(&ecDefineH, "ec-define-h", "1", "Defines cofactor 'h' of the Elliptic Curve in hex format.")
	flag.BoolVar(&ecDot, "ec-dot", false, "Performs addition of points P and Q on the Elliptic Curve. Returns result as hex values.")
	flag.StringVar(&ecDotPx, "ec-dot-px", "7867AC344228C91EABACBE0FBB78DA0FE1E5A4D298467811", "Specifies P's x-coordinate.")
	flag.StringVar(&ecDotPy, "ec-dot-py", "8C0855236B4F79655A0CBDF18E6125771792524D4DBFD1FE", "Specifies P's y-coordinate.")
	flag.StringVar(&ecDotQx, "ec-dot-qx", "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", "Specifies Q's x-coordinate.")
	flag.StringVar(&ecDotQy, "ec-dot-qy", "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", "Specifies Q's y-coordinate.")
	flag.BoolVar(&ecTrapdoor, "ec-trapdoor", false, "Performs scalar multiplication operation of Point G on Elliptic Curve.")
	flag.StringVar(&ecTrapdoorK, "ec-trapdoor-k", "B", "Specifies scalar K in hex format.")
	flag.StringVar(&ecTrapdoorGx, "ec-trapdoor-gx", "7867AC344228C91EABACBE0FBB78DA0FE1E5A4D298467811", "Specifies Point G's x-coordinate.")
	flag.StringVar(&ecTrapdoorGy, "ec-trapdoor-gy", "8C0855236B4F79655A0CBDF18E6125771792524D4DBFD1FE", "Specifies Point G's y-coordinate.")

	// ECDH
	var ecdhPrivateKey string
	var ecdh, ecdhGetPublicKey, ecdhECDefine, ecdhToShare bool
	var ecdhECGet, ecdhECDefineP, ecdhECDefineA, ecdhECDefineB, ecdhECDefineGx, ecdhECDefineGy, ecdhECDefineN, ecdhECDefineH, ecdhToSharePx, ecdhToSharePy string

	flag.BoolVar(&ecdh, "ecdh", false, "Enables Elliptic Curve Diffie Hellman protocol.")
	flag.StringVar(&ecdhECGet, "ecdh-ec-get", "secp192k1", "Identifies Elliptic Curve for protocol usage. Supported curves: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.")
	flag.BoolVar(&ecdhECDefine, "ecdh-ec-define", false, "Enables definition of a new Elliptic Curve.")
	flag.StringVar(&ecdhECDefineP, "ecdh-ec-define-p", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", "Defines 'p' modulus for new curve in hex format.")
	flag.StringVar(&ecdhECDefineA, "ecdh-ec-define-a", "0", "Defines 'a' coefficient for new curve in hex format.")
	flag.StringVar(&ecdhECDefineB, "ecdh-ec-define-b", "3", "Defines 'b' coefficient for new curve in hex format.")
	flag.StringVar(&ecdhECDefineGx, "ecdh-ec-define-gx", "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", "Defines base point 'G' x-coordinate for new curve in hex format.")
	flag.StringVar(&ecdhECDefineGy, "ecdh-ec-define-gy", "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", "Defines base point 'G' y-coordinate for new curve in hex format.")
	flag.StringVar(&ecdhECDefineN, "ecdh-ec-define-n", "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", "Defines order 'n' of base point 'G' for new curve in hex format.")
	flag.StringVar(&ecdhECDefineH, "ecdh-ec-define-h", "1", "Defines curve cofactor 'h' for new curve in hex format.")
	flag.StringVar(&ecdhPrivateKey, "ecdh-private-key", "5C947F3D515FDCD56D50971B1E8017E692CAC847A0FB47E0", "Specifies private key for ECDH protocol.")
	flag.BoolVar(&ecdhGetPublicKey, "ecdh-get-public-key", false, "Retrieves public key for ECDH protocol. Returns result as hex values.")
	flag.BoolVar(&ecdhToShare, "ecdh-toshare", false, "Generates secure communication channel, returning common point in hex format.")
	flag.StringVar(&ecdhToSharePx, "ecdh-toshare-public-key-px", "", "Specifies public key's x-coordinate.")
	flag.StringVar(&ecdhToSharePy, "ecdh-toshare-public-key-py", "", "Specifies public key's y-coordinate.")

	// ECDSA
	var ecdsaPrivateKey string
	var ecdsa, ecdsaECDefine, ecdsaGetPublicKey, ecdsaSignature, ecdsaVerifySignature bool
	var ecdsaECGet, ecdsaECDefineP, ecdsaECDefineA, ecdsaECDefineB, ecdsaECDefineGx, ecdsaECDefineGy, ecdsaECDefineN, ecdsaECDefineH, ecdsaSignatureMessage string
	var ecdsaVerifySignaturePublicKeyPx, ecdsaVerifySignaturePublicKeyPy, ecdsaVerifySignatureR, ecdsaVerifySignatureS, ecdsaVerifySignatureSignedMessage string

	flag.BoolVar(&ecdsa, "ecdsa", false, "This command enables the Elliptic Curve Digital Signature Algorithm (ECDSA).")
	flag.StringVar(&ecdsaECGet, "ecdsa-ec-get", "secp192k1", "Specify the specific Elliptic Curve for ECDSA. Supported curves: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1")
	flag.BoolVar(&ecdsaECDefine, "ecdsa-ec-define", false, "If set to true, it allows for the definition of new custom Elliptic Curve parameters.")
	flag.StringVar(&ecdsaECDefineP, "ecdsa-ec-define-p", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", "Define prime modulus 'p' of the new Elliptic Curve in hex format.")
	flag.StringVar(&ecdsaECDefineA, "ecdsa-ec-define-a", "0", "Define coefficient 'a' of the new Elliptic Curve in hex format.")
	flag.StringVar(&ecdsaECDefineB, "ecdsa-ec-define-b", "3", "Define coefficient 'b' of the new Elliptic Curve in hex format.")
	flag.StringVar(&ecdsaECDefineGx, "ecdsa-ec-define-gx", "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", "Define x-coordinate of base point 'G' of the new Elliptic Curve in hex format.")
	flag.StringVar(&ecdsaECDefineGy, "ecdsa-ec-define-gy", "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", "Define y-coordinate of base point 'G' of the new Elliptic Curve in hex format.")
	flag.StringVar(&ecdsaECDefineN, "ecdsa-ec-define-n", "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", "Define 'n' order of base point 'G' of the new Elliptic Curve in hex format.")
	flag.StringVar(&ecdsaECDefineH, "ecdsa-ec-define-h", "1", "Define 'h' cofactor of the new Elliptic Curve in hex format.")
	flag.StringVar(&ecdsaPrivateKey, "ecdsa-private-key", "5C947F3D515FDCD56D50971B1E8017E692CAC847A0FB47E0", "Specify the private key for ECDSA in hex format.")
	flag.BoolVar(&ecdsaGetPublicKey, "ecdsa-get-public-key", false, "If set to true, it retrieves the public key for ECDSA as a pair of hexadecimal values PX and PY.")
	flag.BoolVar(&ecdsaSignature, "ecdsa-signature", false, "If set to true, it triggers the generation of an ECDSA signature. Returns the generated signature's R and S values in hexadecimal format.")
	flag.StringVar(&ecdsaSignatureMessage, "ecdsa-signature-message", "", "The source message to be signed, provided in hexadecimal format.")
	flag.BoolVar(&ecdsaVerifySignature, "ecdsa-verify-signature", false, "If set to true, it enables ECDSA signature verification function. Returns 1 if the provided signature is valid, and 0 otherwise.")
	flag.StringVar(&ecdsaVerifySignaturePublicKeyPx, "ecdsa-verify-signature-public-key-px", "", "The x-coordinate of the Public Key used for ECDSA signature verification, provided in hexadecimal format.")
	flag.StringVar(&ecdsaVerifySignaturePublicKeyPy, "ecdsa-verify-signature-public-key-py", "", "The y-coordinate of the Public Key used for ECDSA signature verification, provided in hexadecimal format.")
	flag.StringVar(&ecdsaVerifySignatureR, "ecdsa-verify-signature-r", "", "The 'R' value of the ECDSA signature being verified, provided in hexadecimal format.")
	flag.StringVar(&ecdsaVerifySignatureS, "ecdsa-verify-signature-s", "", "The 'S' value of the ECDSA signature being verified, provided in hexadecimal format.")
	flag.StringVar(&ecdsaVerifySignatureSignedMessage, "ecdsa-verify-signature-signed-message", "", "The original message that was signed with ECDSA, provided in hexadecimal format.")

	// ECK
	var eck, eckECDefine, eckEncode, eckDecode bool
	var eckDecodePx, eckDecodePy, eckDecodeJ string
	var eckECGet, eckECDefineP, eckECDefineA, eckECDefineB, eckECDefineGx, eckECDefineGy, eckECDefineN, eckECDefineH, eckEncodeMessage, eckEncodingType string

	flag.BoolVar(&eck, "eck", false, "Activates Elliptic Curve Cryptography encoding and decoding operations.")
	flag.StringVar(&eckECGet, "eck-ec-get", "secp384r1", "Specifies the Elliptic Curve to be used for operations. Supported curves: Supported curves: secp384r1, secp521r1.")
	flag.StringVar(&eckEncodingType, "eck-encoding-type", "unicode", "Specifies the encoding type to be used. Supported curves: secp384r1, secp521r1 for 'unicode' and secp192k1, secp192r1, secp256k1, secp256r1, secp384r1, secp521r1 for 'ascii'.")
	flag.BoolVar(&eckECDefine, "eck-ec-define", false, "Allows the custom definition of an Elliptic Curve.")
	flag.StringVar(&eckECDefineP, "eck-ec-define-p", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", "Defines 'p', the prime modulus of the Elliptic Curve, in hexadecimal format.")
	flag.StringVar(&eckECDefineA, "eck-ec-define-a", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", "Defines 'a', the coefficient of the Elliptic Curve, in hexadecimal format.")
	flag.StringVar(&eckECDefineB, "eck-ec-define-b", "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", "Defines 'b', the coefficient of the Elliptic Curve, in hexadecimal format.")
	flag.StringVar(&eckECDefineGx, "eck-ec-define-gx", "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", "Defines 'Gx', the x-coordinate of the Elliptic Curve base point 'G', in hexadecimal format.")
	flag.StringVar(&eckECDefineGy, "eck-ec-define-gy", "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", "Defines 'Gy', the y-coordinate of the Elliptic Curve base point 'G', in hexadecimal format.")
	flag.StringVar(&eckECDefineN, "eck-ec-define-n", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", "Defines 'n', the order of the Elliptic Curve base point 'G', in hexadecimal format.")
	flag.StringVar(&eckECDefineH, "eck-ec-define-h", "1", "Defines 'h', the cofactor of the Elliptic Curve, in hexadecimal format.")
	flag.BoolVar(&eckEncode, "eck-encode", false, "Activates the encoding function that converts a string message into a point on the elliptic curve. The output is in hexadecimal format.")
	flag.StringVar(&eckEncodeMessage, "eck-encode-message", "", "Specifies the message to be encoded into a point on the elliptic curve.")
	flag.BoolVar(&eckDecode, "eck-decode", false, "Activates the decoding function that converts a point on the elliptic curve back into a string message.")
	flag.StringVar(&eckDecodePx, "eck-decode-px", "", "Specifies the x-coordinate of the point on the elliptic curve, in hexadecimal format, to be decoded.")
	flag.StringVar(&eckDecodePy, "eck-decode-py", "", "Specifies the y-coordinate of the point on the elliptic curve, in hexadecimal format, to be decoded.")
	flag.StringVar(&eckDecodeJ, "eck-decode-j", "", "Specifies the 'j-invariant' of the elliptic curve point, in hexadecimal format, to be decoded.")

	// ECMO
	var ecmoPrivateKey string
	var ecmo, ecmoECDefine, ecmoGetPublicKey, ecmoEncrypt, ecmoDecrypt, ecmoEncrypt2, ecmoDecrypt2 bool
	var ecmoECGet, ecmoECDefineP, ecmoECDefineA, ecmoECDefineB, ecmoECDefineGx, ecmoECDefineGy, ecmoECDefineN, ecmoECDefineH string
	var ecmoEncryptToSharePublicKeyPx, ecmoEncryptToSharePublicKeyPy, ecmoECKEncodingType, ecmoEncryptMessage, ecmoDecryptPx, ecmoDecryptPy, ecmoDecryptJ, ecmoDecryptR, ecmoDecryptS, ecmoDecryptToSharePublicKeyPx, ecmoDecryptToSharePublicKeyPy, ecmoEncryptPx, ecmoEncryptPy, ecmoEncryptJ, ecmoEncryptR, ecmoEncryptS string

	flag.BoolVar(&ecmo, "ecmo", false, "Activate the Massey–Omura Elliptic Curve protocol.")
	flag.StringVar(&ecmoECGet, "ecmo-ec-get", "secp384r1", "Specify the Elliptic Curve for operations by its identifier. Supported curves: secp384r1, secp521r1.")
	flag.BoolVar(&ecmoECDefine, "ecmo-ec-define", false, "Enable the creation of a new Elliptic Curve.")
	flag.StringVar(&ecmoECDefineP, "ecmo-ec-define-p", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", "Set the 'p' prime modulus of the Elliptic Curve in hexadecimal format.")
	flag.StringVar(&ecmoECDefineA, "ecmo-ec-define-a", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", "Set the 'a' coefficient of the Elliptic Curve in hexadecimal format.")
	flag.StringVar(&ecmoECDefineB, "ecmo-ec-define-b", "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", "Set the 'b' coefficient of the Elliptic Curve in hexadecimal format.")
	flag.StringVar(&ecmoECDefineGx, "ecmo-ec-define-gx", "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", "Set the x-coordinate of the base point 'G' on the Elliptic Curve in hexadecimal format.")
	flag.StringVar(&ecmoECDefineGy, "ecmo-ec-define-gy", "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", "Set the y-coordinate of the base point 'G' on the Elliptic Curve in hexadecimal format.")
	flag.StringVar(&ecmoECDefineN, "ecmo-ec-define-n", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", "Set the order 'n' of the base point 'G' on the Elliptic Curve in hexadecimal format.")
	flag.StringVar(&ecmoECDefineH, "ecmo-ec-define-h", "1", "Set the cofactor 'h' of the Elliptic Curve in hexadecimal format.")
	flag.StringVar(&ecmoPrivateKey, "ecmo-private-key", "5C947F3D515FDCD56D50971B1E8017E692CAC847A0FB47E0", "Specify the private key for the Elliptic Curve Massey–Omura protocol in hexadecimal format.")
	flag.BoolVar(&ecmoGetPublicKey, "ecmo-get-public-key", false, "Retrieve the public key for the Massey–Omura protocol. Outputs in Hex(PX) Hex(PY) format.")
	flag.StringVar(&ecmoECKEncodingType, "ecmo-eck-encoding-type", "unicode", "Specifies the encoding type to be used. Supported curves: secp384r1, secp521r1 for 'unicode' and secp192k1, secp192r1, secp256k1, secp256r1, secp384r1, secp521r1 for 'ascii'.")
	flag.BoolVar(&ecmoEncrypt, "ecmo-encrypt", false, "Encode a message using the Massey–Omura protocol, outputs in Hex(Px), Hex(Py), Hex(J), Hex(R), Hex(S) format.")
	flag.StringVar(&ecmoEncryptMessage, "ecmo-encrypt-message", "", "Specify the message to encode using the Massey–Omura protocol.")
	flag.BoolVar(&ecmoEncrypt2, "ecmo-encrypt2", false, "Encode a message using the Massey–Omura protocol, outputs in Hex(Px), Hex(Py), Hex(J), Hex(R), Hex(S) format.")
	flag.StringVar(&ecmoEncryptPx, "ecmo-encrypt-px", "", "Specify the x-coordinate of the point on the Elliptic Curve to decode. Must be in hexadecimal format.")
	flag.StringVar(&ecmoEncryptPy, "ecmo-encrypt-py", "", "Specify the y-coordinate of the point on the Elliptic Curve to decode. Must be in hexadecimal format.")
	flag.StringVar(&ecmoEncryptJ, "ecmo-encrypt-j", "", "Specify the 'j-invariant' of the Elliptic Curve point. Must be in hexadecimal format.")
	flag.StringVar(&ecmoEncryptR, "ecmo-encrypt-r", "", "Specify the 'r-signature' of the Elliptic Curve point. Must be in hexadecimal format.")
	flag.StringVar(&ecmoEncryptS, "ecmo-encrypt-s", "", "Specify the 's-signature' of the Elliptic Curve point. Must be in hexadecimal format.")
	flag.StringVar(&ecmoEncryptToSharePublicKeyPx, "ecmo-encrypt-toshare-public-key-px", "", "Specify the x-coordinate of the public key to use for encoding.")
	flag.StringVar(&ecmoEncryptToSharePublicKeyPy, "ecmo-encrypt-toshare-public-key-py", "", "Specify the y-coordinate of the public key to use for encoding.")
	flag.BoolVar(&ecmoDecrypt, "ecmo-decrypt", false, "Decode a given point on the Elliptic Curve into a string message.")
	flag.BoolVar(&ecmoDecrypt2, "ecmo-decrypt2", false, "Decode a given point on the Elliptic Curve into a string message.")
	flag.StringVar(&ecmoDecryptPx, "ecmo-decrypt-px", "", "Specify the x-coordinate of the point on the Elliptic Curve to decode. Must be in hexadecimal format.")
	flag.StringVar(&ecmoDecryptPy, "ecmo-decrypt-py", "", "Specify the y-coordinate of the point on the Elliptic Curve to decode. Must be in hexadecimal format.")
	flag.StringVar(&ecmoDecryptJ, "ecmo-decrypt-j", "", "Specify the 'j-invariant' of the Elliptic Curve point. Must be in hexadecimal format.")
	flag.StringVar(&ecmoDecryptR, "ecmo-decrypt-r", "", "Specify the 'r-signature' of the Elliptic Curve point. Must be in hexadecimal format.")
	flag.StringVar(&ecmoDecryptS, "ecmo-decrypt-s", "", "Specify the 's-signature' of the Elliptic Curve point. Must be in hexadecimal format.")
	flag.StringVar(&ecmoDecryptToSharePublicKeyPx, "ecmo-decrypt-toshare-public-key-px", "", "Specify the x-coordinate of the public key to use for decoding.")
	flag.StringVar(&ecmoDecryptToSharePublicKeyPy, "ecmo-decrypt-toshare-public-key-py", "", "Specify the y-coordinate of the public key to use for decoding.")
	flag.Parse()

	if info {
		fmt.Printf("Version: %s\n", CODEVERSION)
		fmt.Printf("Operating System: %s\n", GOOS)
		fmt.Printf("System Architecture: %s\n", GOARCH)
		fmt.Printf("Build Date: %s\n", CODEBUILDDATE)
		fmt.Printf("Build Revision: %s\n", CODEBUILDREVISION)
		return
	}

	if license {
		fmt.Println("Copyright 2023-2024 Isak Ruas")
		fmt.Println("Licensed under the Apache License, Version 2.0 (the 'License');")
		fmt.Println("you may not use this file except in compliance with the License.")
		fmt.Println("You may obtain a copy of the License at")
		fmt.Println("    http://www.apache.org/licenses/LICENSE-2.0")
		fmt.Println("Unless required by applicable law or agreed to in writing, software")
		fmt.Println("distributed under the License is distributed on an 'AS IS' BASIS,")
		fmt.Println("WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.")
		fmt.Println("See the License for the specific language governing permissions and")
		fmt.Println("limitations under the License.")
		return
	}

	if ec {
		P := new(big.Int)
		P.SetString(ecDefineP, 16)

		A := new(big.Int)
		A.SetString(ecDefineA, 16)

		B := new(big.Int)
		B.SetString(ecDefineB, 16)

		Gx := new(big.Int)
		Gx.SetString(ecDefineGx, 16)

		Gy := new(big.Int)
		Gy.SetString(ecDefineGy, 16)

		N := new(big.Int)
		N.SetString(ecDefineN, 16)

		H := new(big.Int)
		H.SetString(ecDefineH, 16)

		curve := pkg_ec.EC{
			P:  P,
			A:  A,
			B:  B,
			Gx: Gx,
			Gy: Gy,
			N:  N,
			H:  H,
		}

		if !ecDefine {
			curve = pkg_ec.Get(ecGet)
		}

		if ecDot {

			Px := new(big.Int)
			Px.SetString(ecDotPx, 16)
			Py := new(big.Int)
			Py.SetString(ecDotPy, 16)

			Pd := pkg_ec.Point{
				Px: Px,
				Py: Py,
			}

			if ecDotPx == "∞" || ecDotPy == "∞" {
				Pd = pkg_ec.Point{}
			}

			Qx := new(big.Int)
			Qx.SetString(ecDotQx, 16)
			Qy := new(big.Int)
			Qy.SetString(ecDotQy, 16)

			Qd := pkg_ec.Point{
				Px: Qx,
				Py: Qy,
			}

			if ecDotQx == "∞" || ecDotQy == "∞" {
				Qd = pkg_ec.Point{}
			}

			R := curve.Dot(
				Pd,
				Qd,
			)

			if R.Px == nil || R.Py == nil {
				fmt.Printf("∞")
				return
			}

			fmt.Printf("%X %X", R.Px, R.Py)
			return
		}
		if ecTrapdoor {
			K := new(big.Int)
			K.SetString(ecTrapdoorK, 16)

			Gx := new(big.Int)
			Gx.SetString(ecTrapdoorGx, 16)
			Gy := new(big.Int)
			Gy.SetString(ecTrapdoorGy, 16)

			Gt := pkg_ec.Point{
				Px: Gx,
				Py: Gy,
			}

			if ecTrapdoorGx == "∞" || ecTrapdoorGy == "∞" {
				Gt = pkg_ec.Point{}
			}

			R := curve.Trapdoor(
				&Gt,
				K,
			)

			if R.Px == nil || R.Py == nil {
				fmt.Printf("∞")
				return
			}

			fmt.Printf("%X %X", R.Px, R.Py)
			return
		}
		flag.PrintDefaults()
		return
	}

	if ecdh {
		P := new(big.Int)
		P.SetString(ecdhECDefineP, 16)

		A := new(big.Int)
		A.SetString(ecdhECDefineA, 16)

		B := new(big.Int)
		B.SetString(ecdhECDefineB, 16)

		Gx := new(big.Int)
		Gx.SetString(ecdhECDefineGx, 16)

		Gy := new(big.Int)
		Gy.SetString(ecdhECDefineGy, 16)

		N := new(big.Int)
		N.SetString(ecdhECDefineN, 16)

		H := new(big.Int)
		H.SetString(ecdhECDefineH, 16)

		curve := pkg_ec.EC{
			P:  P,
			A:  A,
			B:  B,
			Gx: Gx,
			Gy: Gy,
			N:  N,
			H:  H,
		}

		if !ecdhECDefine {
			curve = pkg_ec.Get(ecdhECGet)
		}

		privateKey := new(big.Int)
		privateKey.SetString(ecdhPrivateKey, 16)

		ecdh := pkg_ecdh.ECDH{
			Curve:      &curve,
			PrivateKey: privateKey,
		}

		if ecdhGetPublicKey {
			P := ecdh.PublicKey()
			fmt.Printf("%X %X", P.Px, P.Py)
			return
		}

		if ecdhToShare {
			Px := new(big.Int)
			Px.SetString(ecdhToSharePx, 16)

			Py := new(big.Int)
			Py.SetString(ecdhToSharePy, 16)

			S := ecdh.ToShare(&pkg_ec.Point{
				Px: Px,
				Py: Py,
			})

			fmt.Printf("%X %X", S.Px, S.Py)
			return
		}

		flag.PrintDefaults()
		return
	}

	if ecdsa {
		P := new(big.Int)
		P.SetString(ecdsaECDefineP, 16)

		A := new(big.Int)
		A.SetString(ecdsaECDefineA, 16)

		B := new(big.Int)
		B.SetString(ecdsaECDefineB, 16)

		Gx := new(big.Int)
		Gx.SetString(ecdsaECDefineGx, 16)

		Gy := new(big.Int)
		Gy.SetString(ecdsaECDefineGy, 16)

		N := new(big.Int)
		N.SetString(ecdsaECDefineN, 16)

		H := new(big.Int)
		H.SetString(ecdsaECDefineH, 16)

		curve := pkg_ec.EC{
			P:  P,
			A:  A,
			B:  B,
			Gx: Gx,
			Gy: Gy,
			N:  N,
			H:  H,
		}

		if !ecdsaECDefine {
			curve = pkg_ec.Get(ecdsaECGet)
		}

		privateKey := new(big.Int)
		privateKey.SetString(ecdsaPrivateKey, 16)

		ecdsa := pkg_ecdsa.ECDSA{
			Curve:      &curve,
			PrivateKey: privateKey,
		}

		if ecdsaGetPublicKey {
			P := ecdsa.PublicKey()
			fmt.Printf("%X %X", P.Px, P.Py)
			return
		}

		if ecdsaSignature {

			message := new(big.Int)
			message.SetString(ecdsaSignatureMessage, 16)

			R, S := ecdsa.Signature(message)
			fmt.Printf("%X %X", R, S)
			return
		}

		if ecdsaVerifySignature {

			R := new(big.Int)
			R.SetString(ecdsaVerifySignatureR, 16)

			S := new(big.Int)
			S.SetString(ecdsaVerifySignatureS, 16)

			message := new(big.Int)
			message.SetString(ecdsaVerifySignatureSignedMessage, 16)

			Px := new(big.Int)
			Px.SetString(ecdsaVerifySignaturePublicKeyPx, 16)

			Py := new(big.Int)
			Py.SetString(ecdsaVerifySignaturePublicKeyPy, 16)

			publicKey := pkg_ec.Point{
				Px: Px,
				Py: Py,
			}

			if ecdsa.VerifySignature(message, R, S, &publicKey) {
				fmt.Printf("1")
				return
			}

			fmt.Printf("0")
			return
		}

		flag.PrintDefaults()
		return
	}

	if eck {
		P := new(big.Int)
		P.SetString(eckECDefineP, 16)

		A := new(big.Int)
		A.SetString(eckECDefineA, 16)

		B := new(big.Int)
		B.SetString(eckECDefineB, 16)

		Gx := new(big.Int)
		Gx.SetString(eckECDefineGx, 16)

		Gy := new(big.Int)
		Gy.SetString(eckECDefineGy, 16)

		N := new(big.Int)
		N.SetString(eckECDefineN, 16)

		H := new(big.Int)
		H.SetString(eckECDefineH, 16)

		curve := pkg_ec.EC{
			P:  P,
			A:  A,
			B:  B,
			Gx: Gx,
			Gy: Gy,
			N:  N,
			H:  H,
		}

		if !eckECDefine {
			curve = pkg_ec.Get(eckECGet)
		}

		eck := pkg_eck.ECK{
			Curve:        &curve,
			EncodingType: eckEncodingType,
		}

		if eckEncode {
			P, j := eck.Encode(eckEncodeMessage)
			fmt.Printf("%X %X %X", P.Px, P.Py, j)
			return
		}

		if eckDecode {

			Px := new(big.Int)
			Px.SetString(eckDecodePx, 16)

			Py := new(big.Int)
			Py.SetString(eckDecodePy, 16)

			J := new(big.Int)
			J.SetString(eckDecodeJ, 16)

			P := pkg_ec.Point{
				Px: Px,
				Py: Py,
			}

			decode := eck.Decode(&P, J)
			fmt.Printf(decode)
			return
		}

		flag.PrintDefaults()
		return
	}

	if ecmo {
		P := new(big.Int)
		P.SetString(ecmoECDefineP, 16)

		A := new(big.Int)
		A.SetString(ecmoECDefineA, 16)

		B := new(big.Int)
		B.SetString(ecmoECDefineB, 16)

		Gx := new(big.Int)
		Gx.SetString(ecmoECDefineGx, 16)

		Gy := new(big.Int)
		Gy.SetString(ecmoECDefineGy, 16)

		N := new(big.Int)
		N.SetString(ecmoECDefineN, 16)

		H := new(big.Int)
		H.SetString(ecmoECDefineH, 16)

		curve := pkg_ec.EC{
			P:  P,
			A:  A,
			B:  B,
			Gx: Gx,
			Gy: Gy,
			N:  N,
			H:  H,
		}

		if !ecmoECDefine {
			curve = pkg_ec.Get(ecmoECGet)
		}

		privateKey := new(big.Int)
		privateKey.SetString(ecmoPrivateKey, 16)

		ecmo := pkg_ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      privateKey,
			ECKEncodingType: ecmoECKEncodingType,
		}

		if ecmoGetPublicKey {
			P := ecmo.PublicKey()
			fmt.Printf("%X %X", P.Px, P.Py)
			return
		}

		// if ecmoEncrypt {
		// 	Px := new(big.Int)
		// 	Px.SetString(ecmoEncryptToSharePublicKeyPx, 16)

		// 	Py := new(big.Int)
		// 	Py.SetString(ecmoEncryptToSharePublicKeyPy, 16)

		// 	bobPublicKey := pkg_ec.Point{
		// 		Px: Px,
		// 		Py: Py,
		// 	}

		// 	P, J, R, S := ecmo.Encrypt(ecmoEncryptMessage, &bobPublicKey)
		// 	fmt.Printf("%X %X %X %X %X", P.Px, P.Py, J, R, S)
		// 	return
		// }

		if ecmoEncrypt {
			Px := new(big.Int)
			Px.SetString(ecmoEncryptToSharePublicKeyPx, 16)

			Py := new(big.Int)
			Py.SetString(ecmoEncryptToSharePublicKeyPy, 16)

			P, J, R, S := ecmo.Encrypt(ecmoEncryptMessage)

			fmt.Printf("%X %X %X %X %X", P.Px, P.Py, J, R, S)
			return
		}
		if ecmoEncrypt2 {
			Px := new(big.Int)
			Px.SetString(ecmoEncryptPx, 16)

			Py := new(big.Int)
			Py.SetString(ecmoEncryptPy, 16)

			P := pkg_ec.Point{
				Px: Px,
				Py: Py,
			}

			J := new(big.Int)
			J.SetString(ecmoEncryptJ, 16)

			R := new(big.Int)
			R.SetString(ecmoEncryptR, 16)

			S := new(big.Int)
			S.SetString(ecmoEncryptS, 16)

			PubKPx := new(big.Int)
			PubKPx.SetString(ecmoEncryptToSharePublicKeyPx, 16)

			PubKPy := new(big.Int)
			PubKPy.SetString(ecmoEncryptToSharePublicKeyPy, 16)

			bobPublicKey := pkg_ec.Point{
				Px: PubKPx,
				Py: PubKPy,
			}

			PEncrypted, JEncrypted, REncrypted, SEncrypted := ecmo.Encrypt2(&P, J, R, S, &bobPublicKey)

			fmt.Printf("%X %X %X %X %X", PEncrypted.Px, PEncrypted.Py, JEncrypted, REncrypted, SEncrypted)
			return
		}

		// if ecmoDecrypt {
		// 	Px := new(big.Int)
		// 	Px.SetString(ecmoDecryptPx, 16)

		// 	Py := new(big.Int)
		// 	Py.SetString(ecmoDecryptPy, 16)

		// 	P := pkg_ec.Point{
		// 		Px: Px,
		// 		Py: Py,
		// 	}

		// 	J := new(big.Int)
		// 	J.SetString(ecmoDecryptJ, 16)

		// 	R := new(big.Int)
		// 	R.SetString(ecmoDecryptR, 16)

		// 	S := new(big.Int)
		// 	S.SetString(ecmoDecryptS, 16)

		// 	PubKPx := new(big.Int)
		// 	PubKPx.SetString(ecmoDecryptToSharePublicKeyPx, 16)

		// 	PubKPy := new(big.Int)
		// 	PubKPy.SetString(ecmoDecryptToSharePublicKeyPy, 16)

		// 	alicePublicKey := pkg_ec.Point{
		// 		Px: PubKPx,
		// 		Py: PubKPy,
		// 	}

		// 	decrypt := ecmo.Decrypt(&P, J, R, S, &alicePublicKey)
		// 	fmt.Printf(decrypt)
		// 	return
		// }

		if ecmoDecrypt {
			Px := new(big.Int)
			Px.SetString(ecmoDecryptPx, 16)

			Py := new(big.Int)
			Py.SetString(ecmoDecryptPy, 16)

			P := pkg_ec.Point{
				Px: Px,
				Py: Py,
			}

			J := new(big.Int)
			J.SetString(ecmoDecryptJ, 16)

			R := new(big.Int)
			R.SetString(ecmoDecryptR, 16)

			S := new(big.Int)
			S.SetString(ecmoDecryptS, 16)

			PubKPx := new(big.Int)
			PubKPx.SetString(ecmoDecryptToSharePublicKeyPx, 16)

			PubKPy := new(big.Int)
			PubKPy.SetString(ecmoDecryptToSharePublicKeyPy, 16)

			alicePublicKey := pkg_ec.Point{
				Px: PubKPx,
				Py: PubKPy,
			}

			PDecrypted, JDecrypted, RDecrypted, SDecrypted := ecmo.Decrypt(&P, J, R, S, &alicePublicKey)

			fmt.Printf("%X %X %X %X %X", PDecrypted.Px, PDecrypted.Py, JDecrypted, RDecrypted, SDecrypted)
			return
		}

		if ecmoDecrypt2 {
			Px := new(big.Int)
			Px.SetString(ecmoDecryptPx, 16)

			Py := new(big.Int)
			Py.SetString(ecmoDecryptPy, 16)

			P := pkg_ec.Point{
				Px: Px,
				Py: Py,
			}

			J := new(big.Int)
			J.SetString(ecmoDecryptJ, 16)

			R := new(big.Int)
			R.SetString(ecmoDecryptR, 16)

			S := new(big.Int)
			S.SetString(ecmoDecryptS, 16)

			PubKPx := new(big.Int)
			PubKPx.SetString(ecmoDecryptToSharePublicKeyPx, 16)

			PubKPy := new(big.Int)
			PubKPy.SetString(ecmoDecryptToSharePublicKeyPy, 16)

			alicePublicKey := pkg_ec.Point{
				Px: PubKPx,
				Py: PubKPy,
			}

			decrypt := ecmo.Decrypt2(&P, J, R, S, &alicePublicKey)
			fmt.Printf(decrypt)
			return
		}

		flag.PrintDefaults()
		return
	}

	flag.PrintDefaults()
}
