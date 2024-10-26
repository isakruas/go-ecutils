# *Software* Documentation "ecutils"

## *Software* Name
**ecutils**

## Version of the *Software*
**1.1.2**

## *Software* Description

*ecutils* is a cryptography application that offers a variety of features and functionalities for Elliptic Curve operations. This *software* was designed to meet the needs of cybersecurity professionals, software developers, and anyone requiring high-level cryptographic operations in their activities.

## Author

* **Isak Paulo de Andrade Ruas** - Specialist in Elliptic Curve Cryptography

## Purpose

The main objective of *ecutils* is to facilitate the execution of advanced cryptographic operations using Elliptic Curves, ensuring both data security and privacy.

## Key Features

* **Elliptic Curve Generation:** The software allows the definition and creation of new Elliptic Curves, with flexibility in specifying coefficients, coordinates, and other essential parameters.

* **Elliptic Curve Operations:** Commands such as point addition, scalar multiplication, and point operations are supported, making it possible to perform complex cryptographic calculations.

* **Support for Security Protocols:** *ecutils* supports a variety of Elliptic Curve-based security protocols, such as Diffie-Hellman, Digital Signature, and the Massey–Omura protocol.

## Commands Descriptions

Here are detailed descriptions of the commands available in the *ecutils* software:

## General Commands
### -info
Show information about the program’s build and version

### -license
Show information about the program’s license

## Elliptic Curve Operations

### -ec
This command activates Elliptic Curve operations.

### -ec-define
This command activates the definition of a new Elliptic Curve.

### -ec-define-a string
This command allows you to define the 'a' coefficient of the Elliptic Curve in hexadecimal format.

### -ec-define-b string
This command allows you to define the 'b' coefficient of the Elliptic Curve in hexadecimal format.

### -ec-define-gx string
This command allows you to define the 'G' point's x-coordinate on the Elliptic Curve in hexadecimal format.

### -ec-define-gy string
This command allows you to define the 'G' point's y-coordinate on the Elliptic Curve in hexadecimal format.

### -ec-define-h string
This command allows you to define the Elliptic Curve's cofactor 'h' in hexadecimal format.

### -ec-define-n string
This command allows you to define the order 'n' of the 'G' base point on the Elliptic Curve in hexadecimal format.

### -ec-define-p string
This command allows you to define the Elliptic Curve's prime modulus 'p' in hexadecimal format.

### -ec-dot
This command performs the addition of points P and Q on the Elliptic Curve and returns the result in hexadecimal values.

### -ec-dot-px string
This command specifies the x-coordinate of point P.

### -ec-dot-py string
This command specifies the y-coordinate of point P.

### -ec-dot-qx string
This command specifies the x-coordinate of point Q.

### -ec-dot-qy string
This command specifies the y-coordinate of point Q.

### -ec-get string
This command identifies the Elliptic Curve for operations. Supported Curves: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.

### -ec-trapdoor
This command performs scalar multiplication of the base point G on the Elliptic Curve.

### -ec-trapdoor-gx string
This command specifies the x-coordinate of point G.

### -ec-trapdoor-gy string
This command specifies the y-coordinate of point G.

### -ec-trapdoor-k string
Specifies the scalar K in hexadecimal format. (default "B")

## Elliptic Curve Diffie-Hellman Key Exchange Protocol (ECDH)

### -ecdh
This command activates the Elliptic Curve Diffie Hellman (ECDH) key exchange protocol.

### -ecdh-ec-define
This command activates the definition of a new Elliptic Curve for ECDH.

### -ecdh-ec-define-a string
This command allows you to define the 'a' coefficient for the new curve in hexadecimal format.

### -ecdh-ec-define-b string
This command allows you to define the 'b' coefficient for the new curve in hexadecimal format.

### -ecdh-ec-define-gx string
This command allows you to define the 'G' point's x-coordinate for the new curve in hexadecimal format.

### -ecdh-ec-define-gy string
This command allows you to define the 'G' point's y-coordinate for the new curve in hexadecimal format.

### -ecdh-ec-define-h string
This command allows you to define the cofactor 'h' for the new curve in hexadecimal format.

### -ecdh-ec-define-n string
This command allows you to define the 'G' point's order 'n' for the new curve in hexadecimal format.

### -ecdh-ec-define-p string
This command allows you to define the prime modulus 'p' of the new curve in hexadecimal format.

### -ecdh-ec-get string
This command identifies the Elliptic Curve to be used in the ECDH protocol. Supported Curves: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.

### -ecdh-get-public-key
This command retrieves the public key for the ECDH protocol and returns the result in hexadecimal values.

### -ecdh-private-key string
This command specifies the private key for the ECDH protocol in hexadecimal format.

### -ecdh-toshare
This command generates a secure communication channel, returning a common point in hexadecimal format.

### -ecdh-toshare-public-key-px string
This command specifies the x-coordinate of the public key.

### -ecdh-toshare-public-key-py string
This command specifies the y-coordinate of the public key.

## Elliptic Curve Digital Signature Algorithm (ECDSA)

### -ecdsa
This command activates the Elliptic Curve Digital Signature Algorithm (ECDSA).

### -ecdsa-ec-define
When set to true, allows the definition of customized Elliptic Curve parameters.

### -ecdsa-ec-define-a string
This command allows you to define the 'a' coefficient of the new Elliptic Curve in hexadecimal format.

### -ecdsa-ec-define-b string
This command allows you to define the 'b' coefficient of the new Elliptic Curve in hexadecimal format.

### -ecdsa-ec-define-gx string
This command allows you to define the 'G' base point’s x-coordinate for the new Elliptic Curve in hexadecimal format.

### -ecdsa-ec-define-gy string
This command allows you to define the 'G' base point’s y-coordinate of the new Elliptic Curve in hexadecimal format.

### -ecdsa-ec-define-h string
This command allows you to define the Elliptic Curve's cofactor 'h' in hexadecimal format.

### -ecdsa-ec-define-n string
This command allows you to define the Elliptic Curve's 'G' point’s order 'n' in hexadecimal format.

### -ecdsa-ec-define-p string
This command allows you to define the Elliptic Curve's prime modulus 'p' in hexadecimal format.

### -ecdsa-ec-get string
Specifies the specific Elliptic Curve for ECDSA. Supported Curves: secp192k1, secp192r1, secp224k1, secp224r1, secp256k1, secp256r1, secp384r1, secp521r1.

### -ecdsa-get-public-key
If set to true, retrieves the public key for ECDSA as a pair of hexadecimal values PX and PY.

### -ecdsa-private-key string
This command specifies the private key for ECDSA in hexadecimal format.

### -ecdsa-signature
If set to true, generates an ECDSA signature. Returns the R and S values of the generated signature in hexadecimal format.

### -ecdsa-signature-message string
This command specifies the source message to be signed, provided in hexadecimal format.

### -ecdsa-verify-signature
If set to true, enables ECDSA signature verification. Returns 1 if the provided signature is valid and 0 otherwise.

### -ecdsa-verify-signature-public-key-px string
This command specifies the x-coordinate of the Public Key used to verify the ECDSA signature, provided in hexadecimal format.

### -ecdsa-verify-signature-public-key-py string
This command specifies the y-coordinate of the Public Key used to verify the ECDSA signature, provided in hexadecimal format.

### -ecdsa-verify-signature-r string
This command specifies the signature’s 'R' value to be verified, provided in hexadecimal format.

### -ecdsa-verify-signature-s string
This command specifies the signature’s 'S' value to be verified, provided in hexadecimal format.

### -ecdsa-verify-signature-signed-message string
This command specifies the original message that was signed with ECDSA, provided in hexadecimal format.

## Elliptic Curve Encoding and Decoding in Cryptography

### -eck
This command activates encoding and decoding operations in Elliptic Curve Cryptography.

### -eck-decode
This command activates the decode function that converts a point on the elliptic curve back to a message string.

### -eck-decode-j string
This command specifies the 'j-invariant' of the elliptic curve point, in hexadecimal format, to be decoded.

### -eck-decode-px string
This command specifies the x-coordinate of the elliptic curve point, in hexadecimal format, to be decoded.

### -eck-decode-py string
This command specifies the y-coordinate of the elliptic curve point, in hexadecimal format, to be decoded.

### -eck-ec-define
This command allows you to define a custom Elliptic Curve.

### -eck-ec-define-a string
This command defines 'a', the Elliptic Curve coefficient, in hexadecimal format.

### -eck-ec-define-b string
This command defines 'b', the Elliptic Curve coefficient, in hexadecimal format.

### -eck-ec-define-gx string
This command defines 'Gx', the x-coordinate of the base point 'G' on the Elliptic Curve, in hexadecimal format.

### -eck-ec-define-gy string
This command defines 'Gy', the y-coordinate of the base point 'G' on the Elliptic Curve, in hexadecimal format.

### -eck-ec-define-h string
This command defines 'h', the Elliptic Curve’s cofactor, in hexadecimal format.

### -eck-ec-define-n string
This command defines 'n', the order of the base point 'G' on the Elliptic Curve, in hexadecimal format.

### -eck-ec-define-p string
This command defines 'p', the Elliptic Curve’s prime modulus, in hexadecimal format.

### -eck-ec-get string
This command specifies the Elliptic Curve for operations. Supported Curves: secp384r1, secp521r1.

### -eck-encoding-type
This command specifies the type of encoding to be used. It supports the following curves for 'unicode': secp384r1 and secp521r1, and the following curves for 'ascii': secp192k1, secp192r1, secp256k1, secp256r1, secp384r1, and secp521r1. The default value is 'unicode.'

### -eck-encode
This command activates the encode function that converts a message string into a point on the elliptic curve. The output is in hexadecimal format.

### -eck-encode-message string
This command specifies the message to be encoded into a point on the elliptic curve.

## Massey–Omura Elliptic Curve Protocol

### -ecmo
This command activates the Massey–Omura Elliptic Curve protocol.

### -ecmo-decrypt
This command decodes a given point on the Elliptic Curve into a message string.

### -ecmo-decrypt-j string
This command specifies the 'j-invariant' of the point on the Elliptic Curve, which should be in hexadecimal format.

### -ecmo-decrypt-px string
This command specifies the x-coordinate of the point on the Elliptic Curve to be decoded. It should be in hexadecimal format.

### -ecmo-decrypt-py string
This command specifies the y-coordinate of the point on the Elliptic Curve to be decoded. It should be in hexadecimal format.

### -ecmo-decrypt-r string
This command specifies the 'r-signature' of the point on the Elliptic Curve. It should be in hexadecimal format.

### -ecmo-decrypt-s string
This command specifies the 's-signature' of the point on the Elliptic Curve. It should be in hexadecimal format.

### -ecmo-decrypt-toshare-public-key-px string
This command specifies the x-coordinate of the public key to be used for decryption.

### -ecmo-decrypt-toshare-public-key-py string
This command specifies the y-coordinate of the public key to be used for decryption.

### -ecmo-ec-define
This command activates the creation of a new Elliptic Curve.

### -ecmo-ec-define-a string
This command defines the 'a' coefficient of the Elliptic Curve in hexadecimal format.

### -ecmo-ec-define-b string
This command defines the 'b' coefficient of the Elliptic Curve in hexadecimal format.

### -ecmo-ec-define-gx string
This command defines 'Gx', the x-coordinate of the base point 'G' on the Elliptic Curve, in hexadecimal format.

### -ecmo-ec-define-gy string
This command defines 'Gy', the y-coordinate of the base point 'G' on the Elliptic Curve, in hexadecimal format.

### -ecmo-ec-define-h string
This command defines 'h', the cofactor of the Elliptic Curve in hexadecimal format.

### -ecmo-ec-define-n string
This command defines 'n', the order of the base point 'G' on the Elliptic Curve in hexadecimal format.

### -ecmo-ec-define-p string
This command defines 'p', the prime modulus 'p' of the Elliptic Curve in hexadecimal format.

### -ecmo-eck-encoding-type
This command specifies the type of encoding to be used. It supports the following curves for 'unicode': secp384r1 and secp521r1, and the following curves for 'ascii': secp192k1, secp192r1, secp256k1, secp256r1, secp384r1, and secp521r1. The default value is 'unicode'.

### -ecmo-ec-get string
This command specifies the Elliptic Curve for operations. Supported Curves: secp384r1, secp521r1.

### -ecmo-encrypt
This command encrypts a message string into a point on the Elliptic Curve. The output is in hexadecimal format.

### -ecmo-encrypt-message string
This command specifies the message to be encrypted.

### -ecmo-encrypt-toshare-public-key-px string
This command specifies the x-coordinate of the public key to be used for encryption.

### -ecmo-encrypt-toshare-public-key-py string
This command specifies the y-coordinate of the public key to be used for encryption.

### -ecmo-get-public-key
This command retrieves the public key for the Massey–Omura protocol. The output is in the format Hex(PX) Hex(PY).

### -ecmo-private-key string
This command specifies the private key for the Elliptic Curve Massey–Omura protocol in hexadecimal format.

## Usage Examples

First, let’s define some parameters to use during the tests:

```bash
#!/bin/bash

# Declares an associative array named elliptic_curves to store the elliptic curve parameters.
declare -A elliptic_curves

# Define the elliptic curve parameters in the elliptic_curves array.
# Each curve is identified by a name, such as "secp192k1", and has parameters like P, A, B, Gx, Gy, N, and H.
elliptic_curves["secp192k1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37"
elliptic_curves["secp192k1,A"]="0"
elliptic_curves["secp192k1,B"]="3"
elliptic_curves["secp192k1,Gx"]="DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
elliptic_curves["secp192k1,Gy"]="9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"
elliptic_curves["secp192k1,N"]="FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D"
elliptic_curves["secp192k1,H"]="1"

elliptic_curves["secp192r1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"
elliptic_curves["secp192r1,A"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"
elliptic_curves["secp192r1,B"]="64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"
elliptic_curves["secp192r1,Gx"]="188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
elliptic_curves["secp192r1,Gy"]="07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"
elliptic_curves["secp192r1,N"]="FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"
elliptic_curves["secp192r1,H"]="1"

elliptic_curves["secp224k1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D"
elliptic_curves["secp224k1,A"]="000000000"
elliptic_curves["secp224k1,B"]="000000005"
elliptic_curves["secp224k1,Gx"]="A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
elliptic_curves["secp224k1,Gy"]="7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"
elliptic_curves["secp224k1,N"]="010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"
elliptic_curves["secp224k1,H"]="1"

elliptic_curves["secp224r1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"
elliptic_curves["secp224r1,A"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"
elliptic_curves["secp224r1,B"]="B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"
elliptic_curves["secp224r1,Gx"]="B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
elliptic_curves["secp224r1,Gy"]="BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"
elliptic_curves["secp224r1,N"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"
elliptic_curves["secp224r1,H"]="1"

elliptic_curves["secp256k1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
elliptic_curves["secp256k1,A"]="00000000000000000"
elliptic_curves["secp256k1,B"]="00000000000000007"
elliptic_curves["secp256k1,Gx"]="79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
elliptic_curves["secp256k1,Gy"]="483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
elliptic_curves["secp256k1,N"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
elliptic_curves["secp256k1,H"]="0000000"

elliptic_curves["secp256r1,P"]="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
elliptic_curves["secp256r1,A"]="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
elliptic_curves["secp256r1,B"]="5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
elliptic_curves["secp256r1,Gx"]="6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
elliptic_curves["secp256r1,Gy"]="4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
elliptic_curves["secp256r1,N"]="FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
elliptic_curves["secp256r1,H"]="1"

elliptic_curves["secp384r1,P"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
elliptic_curves["secp384r1,A"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"
elliptic_curves["secp384r1,B"]="B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
elliptic_curves["secp384r1,Gx"]="AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
elliptic_curves["secp384r1,Gy"]="3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
elliptic_curves["secp384r1,N"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
elliptic_curves["secp384r1,H"]="1"

elliptic_curves["secp521r1,P"]="01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
elliptic_curves["secp521r1,A"]="01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"
elliptic_curves["secp521r1,B"]="0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"
elliptic_curves["secp521r1,Gx"]="00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
elliptic_curves["secp521r1,Gy"]="011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
elliptic_curves["secp521r1,N"]="01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
elliptic_curves["secp521r1,H"]="1"

# Define a list of elliptic curve names to be used later.
curve_names=("secp192k1" "secp192r1" "secp224k1" "secp224r1" "secp256k1" "secp256r1" "secp384r1" "secp521r1")
```

### Testing EC

```bash
# Start script execution and display an informational message.
echo "  >  Testing EC: ..."

# Get the start time of the loop execution.
start_time=$(date +%s%N)

# Loop through the defined elliptic curves.
for curve in "${curve_names[@]}"; do
    # Extract the name of the curve (e.g. "secp192k1") from the curve variable.
    curve_name="${curve%,*}"

    # Get the parameters of the elliptic curve from the elliptic_curves array.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Perform a trapdoor operation with the curve parameters and get the result in R.
    R=$(./ecutils -ec -ec-get "$curve_name" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy")

    # Perform a curve definition and trapdoor operation with the same parameters and get the result in S.
    S=$(./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy")

    # Compare the R and S results obtained above and check if they are equal.
    if [ "$R" != "$S" ]; then
        echo "  >  EC Error: $R != $S"
        exit 1
    fi
    
    # Extract the X and Y coordinates from the R result.
    Qx=$(echo "$R" | cut -d' ' -f1)
    Qy=$(echo "$R" | cut -d' ' -f2)
    
    # Perform a point operation with the extracted coordinates and get the result in R.
    R=$(./ecutils -ec -ec-get "$curve_name" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy")

    # Perform a curve definition and point operation with the same parameters and get the result in S.
    S=$(./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy")

    # Compare the R and S results obtained above and check if they are equal.
    if [ "$R" != "$S" ]; then
        echo "  >  EC Error: $R != $S"
        exit 1
    fi
done

# Get the end time of the loop execution.
end_time=$(date +%s%N)

# Calculate the total loop execution time and display it.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"
```

### Testing ECDH

```bash
# Display an informational message indicating that ECDH tests are being run.
echo "  >  Testing ECDH: ..."

# Get the start time of the loop execution.
start_time=$(date +%s%N)

# Loop through the defined elliptic curves.
for curve in "${curve_names[@]}"; do
    # Extract the name of the curve (e.g. "secp192k1") from the curve variable.
    curve_name="${curve%,*}"

    # Get the parameters of the elliptic curve from the elliptic_curves array.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Execute public key generation using ECDH and store the result in R.
    R=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key F -ecdh-get-public-key)

    # Execute curve definition and public key generation using ECDH and store the result in S.
    S=$(./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-get-public-key)

    # Compare the R and S results obtained above and check if they are equal.
    if [ "$R" != "$S" ]; then
        echo "  >  ECDH Error: $R != $S"
        exit 1
    fi
    
    # Execute the generation of another public key using ECDH, with a private key (B).
    B2=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key B -ecdh-get-public-key)
    BPx=$(echo "$B2" | cut -d' ' -f1)
    BPy=$(echo "$B2" | cut -d' ' -f2)
    
    # Execute public key generation for another entity (F) using ECDH.
    F=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key F -ecdh-get-public-key)
    FPx=$(echo "$F" | cut -d' ' -f1)
    FPy=$(echo "$F" | cut -d' ' -f2)
    
    # Perform ECDH key sharing operation using B and F's private and public keys, and store the result in U.
    U=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key B -ecdh-toshare -ecdh-toshare-public-key-px "$FPx" -ecdh-toshare-public-key-py "$FPy")

    # Perform curve definition and ECDH key sharing operation using B and F's private and public keys, storing the result in V.
    V=$(./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-toshare -ecdh-toshare-public-key-px "$BPx" -ecdh-toshare-public-key-py "$BPy")

    # Compare the U and V results obtained above and check if they are equal.
    if [ "$U" != "$V" ]; then
        echo "  >  ECDH Error: $U != $V"
        exit 1
    fi
done

# Get the end time of the loop execution.
end_time=$(date +%s%N)

# Calculate the total loop execution time and display it.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"
```

### Testing ECDSA

```bash
# Display an informational message indicating that ECDSA tests are being run.
echo "  >  Testing ECDSA: ..."

# Get the start time of the loop execution.
start_time=$(date +%s%N)

# Loop through the defined elliptic curves.
for curve in "${curve_names[@]}"; do
    # Extract the name of the curve (e.g. "secp192k1") from the curve variable.
    curve_name="${curve%,*}"

    # Get the parameters of the elliptic curve from the elliptic_curves array.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Execute public key generation using ECDSA and store the result in R.
    R=$(./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-private-key F -ecdsa-get-public-key)

    # Execute curve definition and public key generation using ECDSA and store the result in S.
    S=$(./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-get-public-key)

    # Compare the R and S results obtained above and check if they are equal.
    if [ "$R" != "$S" ]; then
        echo "  >  ECDSA Error: $R != $S"
        exit 1
    fi
    
    # Extract the X and Y coordinates of the public key R.
    RPx=$(echo "$R" | cut -d' ' -f1)
    RPy=$(echo "$R" | cut -d' ' -f2)
    
    # Define a message to be signed with ECDSA.
    message="2F4811D9EC890E12785B32A8D8FB037A180D1A479E3E0D33"
    
    # Execute the ECDSA signature operation using the private key F and the defined message, and store the result in U.
    U=$(./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-signature -ecdsa-signature-message "$message")

    # Extract the "r" and "s" components of the U signature.
    UR=$(echo "$U" | cut -d' ' -f1)
    US=$(echo "$U" | cut -d' ' -f2)
    
    # Execute the ECDSA signature verification operation using the R public key and the U signature, and store the result in V.
    V=$(./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-verify-signature -ecdsa-verify-signature-public-key-px "$RPx" -ecdsa-verify-signature-public-key-py "$RPy" -ecdsa-verify-signature-r "$UR" -ecdsa-verify-signature-s "$US" -ecdsa-verify-signature-signed-message "$message")
    
    # Verify if the signature verification result equals "1", indicating that the signature is valid.
    if [ "$V" != "1" ]; then
        echo "ECDSA Error"
        exit 1
    fi
done

# Get the end time of the loop execution.
end_time=$(date +%s%N)

# Calculate the total loop execution time and display it.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"
```

### Testing ECK

```bash
# Display an informational message indicating that ECK tests are being run.
echo "  >  Testing ECK: ..."

# Define the elliptic curves to be tested.
curve_names=("secp384r1" "secp521r1")

# Get the start time of the loop execution.
start_time=$(date +%s%N)

# Loop through the defined elliptic curves.
for curve in "${curve_names[@]}"; do
    # Extract the name of the curve (e.g., "secp192k1") from the curve variable.
    curve_name="${curve%,*}"

    # Get the parameters of the elliptic curve from the elliptic_curves array.
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    # Generate a random message.
    message=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 23 | head -n 1)
    
    # Perform elliptic curve definition and message encoding using ECK.
    R=$(./ecutils -eck -eck-ec-define -eck-ec-define-p "$P" -eck-ec-define-a "$A" -eck-ec-define-b "$B" -eck-ec-define-gx "$Gx" -eck-ec-define-gy "$Gy" -eck-ec-define-n "$N" -eck-ec-define-h "$H" -eck-encode -eck-encode-message "$message")
 
    # Extract the X, Y, and J coordinates from the R encoding.
    Px=$(echo "$R" | cut -d' ' -f1)
    Py=$(echo "$R" | cut -d' ' -f2)
    J=$(echo "$R" | cut -d' ' -f3)
    
    # Perform message decoding operation using the coordinates Px, Py, and J, and get the message in S.
    S=$(./ecutils -eck -eck-ec-get "$curve_name" -eck-decode -eck-decode-px "$Px" -eck-decode-py "$Py" -eck-decode-j "$J")
  
    # Compare the original message with the decoded message and check if they are equal.
    if [ "$message" != "$S" ]; then
        echo "  >  ECK Error: $message != $S"
        exit 1
    fi
    
done

# Get the end time of the loop execution.
end_time=$(date +%s%N)

# Calculate the total loop execution time and display it.
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"
```

### Testing ECMO

```bash
# Display an informational message indicating that ECMO tests are being run.
echo "  >  Testing ECMO ASCII: ..."
curve_names=("secp192k1" "secp192r1" "secp256k1" "secp256r1" "secp384r1" "secp521r1")
start_time=$(date +%s%N)
for curve in "${curve_names[@]}"; do
    
    curve_name="${curve%,*}"
    
    P="${elliptic_curves[$curve_name,P]}"
    A="${elliptic_curves[$curve_name,A]}"
    B="${elliptic_curves[$curve_name,B]}"
    Gx="${elliptic_curves[$curve_name,Gx]}"
    Gy="${elliptic_curves[$curve_name,Gy]}"
    N="${elliptic_curves[$curve_name,N]}"
    H="${elliptic_curves[$curve_name,H]}"
    
    R=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key F -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key F -ecmo-get-public-key"
    
    S=$(./ecutils -ecmo -ecmo-ec-define -ecmo-ec-define-p "$P" -ecmo-ec-define-a "$A" -ecmo-ec-define-b "$B" -ecmo-ec-define-gx "$Gx" -ecmo-ec-define-gy "$Gy" -ecmo-ec-define-n "$N" -ecmo-ec-define-h "$H" -ecmo-private-key F -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-define -ecmo-ec-define-p "$P" -ecmo-ec-define-a "$A" -ecmo-ec-define-b "$B" -ecmo-ec-define-gx "$Gx" -ecmo-ec-define-gy "$Gy" -ecmo-ec-define-n "$N" -ecmo-ec-define-h "$H" -ecmo-private-key F -ecmo-get-public-key"
    
    if [ "$R" != "$S" ]; then
        echo "  >  ECMO GetPublicKey Error: $R != $S"
        exit 1
    fi
    
    message=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 23 | head -n 1)
    
    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt -ecmo-encrypt-message "$message")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt -ecmo-encrypt-message "$message""
    
    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)
    
    ALI=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key"
    
    ALIPx=$(echo "$ALI" | cut -d' ' -f1)
    ALIPy=$(echo "$ALI" | cut -d' ' -f2)

    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt2 -ecmo-encrypt-px "$EPx" -ecmo-encrypt-py "$EPy" -ecmo-encrypt-j "$EJ" -ecmo-encrypt-r "$ER" -ecmo-encrypt-s "$ES" -ecmo-encrypt-toshare-public-key-px "$ALIPx" -ecmo-encrypt-toshare-public-key-py "$ALIPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt2 -ecmo-encrypt-px "$EPx" -ecmo-encrypt-py "$EPy" -ecmo-encrypt-j "$EJ" -ecmo-encrypt-r "$ER" -ecmo-encrypt-s "$ES" -ecmo-encrypt-toshare-public-key-px "$ALIPx" -ecmo-encrypt-toshare-public-key-py "$ALIPy""
    
    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)
    
    BOB=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key"
    
    BOBPx=$(echo "$BOB" | cut -d' ' -f1)
    BOBPy=$(echo "$BOB" | cut -d' ' -f2)

    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$BOBPx" -ecmo-decrypt-toshare-public-key-py "$BOBPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$BOBPx" -ecmo-decrypt-toshare-public-key-py "$BOBPy""

    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)

    D=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt2 -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt2 -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy""

    if [ "$message" != "$D" ]; then
        echo "  >  ECMO Error: $message != $D"
        exit 1
    fi
    
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"
```

## Conclusion
The *ecutils* is a versatile and powerful tool for elliptic curve cryptography-based operations. With features including curve generation, point operations, and support for security protocols, it stands out as a valuable choice for cybersecurity professionals and software developers requiring advanced, secure cryptography. With *ecutils*, complex operations can be performed while keeping data security and privacy at the forefront. Its flexibility and variety of commands make it an essential tool for dealing with cryptography challenges across various applications.