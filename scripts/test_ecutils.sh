#!/bin/bash

declare -A elliptic_curves

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
elliptic_curves["secp224k1,A"]=""
elliptic_curves["secp224k1,B"]="5"
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
elliptic_curves["secp256k1,A"]="0"
elliptic_curves["secp256k1,B"]="7"
elliptic_curves["secp256k1,Gx"]="79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
elliptic_curves["secp256k1,Gy"]="483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
elliptic_curves["secp256k1,N"]="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
elliptic_curves["secp256k1,H"]="0"

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

curve_names=("secp192k1" "secp192r1" "secp224k1" "secp224r1" "secp256k1" "secp256r1" "secp384r1" "secp521r1")
echo "  >  Testing EC: ..."
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
    
    R=$(./ecutils -ec -ec-get "$curve_name" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy")
    echo "  >  ./ecutils -ec -ec-get "$curve_name" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy""
    S=$(./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy")
    echo "  >  ./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-trapdoor -ec-trapdoor-k F -ec-trapdoor-gx "$Gx" -ec-trapdoor-gy "$Gy""
    
    if [ "$R" != "$S" ]; then
        echo "  >  EC Trapdoor Error: $R != $S"
        exit 1
    fi
    
    Qx=$(echo "$R" | cut -d' ' -f1)
    Qy=$(echo "$R" | cut -d' ' -f2)
    
    R=$(./ecutils -ec -ec-get "$curve_name" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy")
    echo "  >  ./ecutils -ec -ec-get "$curve_name" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy""
    S=$(./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy")
    echo "  >  ./ecutils -ec -ec-define -ec-define-p "$P" -ec-define-a "$A" -ec-define-b "$B" -ec-define-gx "$Gx" -ec-define-gy "$Gy" -ec-define-n "$N" -ec-define-h "$H" -ec-dot -ec-dot-px "$Gx" -ec-dot-py "$Gy" -ec-dot-qx "$Qx" -ec-dot-qy "$Qy""
    
    if [ "$R" != "$S" ]; then
        echo "  >  EC Dot Error: $R != $S"
        exit 1
    fi
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"

echo "  >  Testing ECDH: ..."
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
    
    R=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key F -ecdh-get-public-key)
    echo "  >  ./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key F -ecdh-get-public-key"
    
    S=$(./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-get-public-key)
    echo "  >  ./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-get-public-key"
    
    if [ "$R" != "$S" ]; then
        echo "  >  ECDH GetPublicKey Error: $R != $S"
        exit 1
    fi
    
    B2=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key B -ecdh-get-public-key)
    BPx=$(echo "$B2" | cut -d' ' -f1)
    BPy=$(echo "$B2" | cut -d' ' -f2)
    
    F=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key F -ecdh-get-public-key)
    FPx=$(echo "$F" | cut -d' ' -f1)
    FPy=$(echo "$F" | cut -d' ' -f2)
    
    U=$(./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key B -ecdh-toshare -ecdh-toshare-public-key-px "$FPx" -ecdh-toshare-public-key-py "$FPy")
    echo "  >  ./ecutils -ecdh -ecdh-ec-get "$curve_name" -ecdh-private-key B -ecdh-toshare -ecdh-toshare-public-key-px "$FPx" -ecdh-toshare-public-key-py "$FPy""
    
    V=$(./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-toshare -ecdh-toshare-public-key-px "$BPx" -ecdh-toshare-public-key-py "$BPy")
    echo "  >  ./ecutils -ecdh -ecdh-ec-define -ecdh-ec-define-p "$P" -ecdh-ec-define-a "$A" -ecdh-ec-define-b "$B" -ecdh-ec-define-gx "$Gx" -ecdh-ec-define-gy "$Gy" -ecdh-ec-define-n "$N" -ecdh-ec-define-h "$H" -ecdh-private-key F -ecdh-toshare -ecdh-toshare-public-key-px "$BPx" -ecdh-toshare-public-key-py "$BPy""
    
    if [ "$U" != "$V" ]; then
        echo "  >  ECDH ToShare Error: $U != $V"
        exit 1
    fi
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"

echo "  >  Testing ECDSA: ..."
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
    
    R=$(./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-private-key F -ecdsa-get-public-key)
    echo "  >  ./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-private-key F -ecdsa-get-public-key"
    
    S=$(./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-get-public-key)
    echo "  >  ./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-get-public-key"
    
    if [ "$R" != "$S" ]; then
        echo "  >  ECDSA GetPublicKey Error: $R != $S"
        exit 1
    fi
    
    RPx=$(echo "$R" | cut -d' ' -f1)
    RPy=$(echo "$R" | cut -d' ' -f2)
    
    message="2F4811D9EC890E12785B32A8D8FB037A180D1A479E3E0D33"
    
    U=$(./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-signature -ecdsa-signature-message "$message")
    echo "  >  ./ecutils -ecdsa -ecdsa-ec-define -ecdsa-ec-define-p "$P" -ecdsa-ec-define-a "$A" -ecdsa-ec-define-b "$B" -ecdsa-ec-define-gx "$Gx" -ecdsa-ec-define-gy "$Gy" -ecdsa-ec-define-n "$N" -ecdsa-ec-define-h "$H" -ecdsa-private-key F -ecdsa-signature -ecdsa-signature-message "$message""
    
    UR=$(echo "$U" | cut -d' ' -f1)
    US=$(echo "$U" | cut -d' ' -f2)
    
    V=$(./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-verify-signature -ecdsa-verify-signature-public-key-px "$RPx" -ecdsa-verify-signature-public-key-py "$RPy" -ecdsa-verify-signature-r "$UR" -ecdsa-verify-signature-s "$US" -ecdsa-verify-signature-signed-message "$message")
    echo "  >  ./ecutils -ecdsa -ecdsa-ec-get "$curve_name" -ecdsa-verify-signature -ecdsa-verify-signature-public-key-px "$RPx" -ecdsa-verify-signature-public-key-py "$RPy" -ecdsa-verify-signature-r "$UR" -ecdsa-verify-signature-s "$US" -ecdsa-verify-signature-signed-message "$message""
    if [ "$V" != "1" ]; then
        echo "ECDSA Signature Error"
        exit 1
    fi
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"

echo "  >  Testing ECK Unicode: ..."
curve_names=("secp384r1" "secp521r1")
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
    
    message=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 23 | head -n 1)
    
    R=$(./ecutils -eck -eck-ec-define -eck-ec-define-p "$P" -eck-ec-define-a "$A" -eck-ec-define-b "$B" -eck-ec-define-gx "$Gx" -eck-ec-define-gy "$Gy" -eck-ec-define-n "$N" -eck-ec-define-h "$H" -eck-encode -eck-encode-message $message)
    echo "  >  ./ecutils -eck -eck-ec-define -eck-ec-define-p "$P" -eck-ec-define-a "$A" -eck-ec-define-b "$B" -eck-ec-define-gx "$Gx" -eck-ec-define-gy "$Gy" -eck-ec-define-n "$N" -eck-ec-define-h "$H" -eck-encode -eck-encode-message $message"
    
    Px=$(echo "$R" | cut -d' ' -f1)
    Py=$(echo "$R" | cut -d' ' -f2)
    J=$(echo "$R" | cut -d' ' -f3)
    
    
    S=$(./ecutils -eck -eck-ec-get "$curve_name" -eck-decode -eck-decode-px "$Px" -eck-decode-py "$Py" -eck-decode-j "$J")
    echo "  >  ./ecutils -eck -eck-ec-get "$curve_name" -eck-decode -eck-decode-px "$Px" -eck-decode-py "$Py" -eck-decode-j "$J""
    
    if [ "$message" != "$S" ]; then
        echo "  >  ECK Error: $message != $S"
        exit 1
    fi
    
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"

echo "  >  Testing ECK ASCII: ..."
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
    
    message=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 23 | head -n 1)
    
    R=$(./ecutils -eck -eck-ec-define -eck-ec-define-p "$P" -eck-ec-define-a "$A" -eck-ec-define-b "$B" -eck-ec-define-gx "$Gx" -eck-ec-define-gy "$Gy" -eck-ec-define-n "$N" -eck-ec-define-h "$H" -eck-encoding-type "ascii" -eck-encode -eck-encode-message $message)
    echo "  >  ./ecutils -eck -eck-ec-define -eck-ec-define-p "$P" -eck-ec-define-a "$A" -eck-ec-define-b "$B" -eck-ec-define-gx "$Gx" -eck-ec-define-gy "$Gy" -eck-ec-define-n "$N" -eck-ec-define-h "$H" -eck-encoding-type "ascii" -eck-encode -eck-encode-message $message"
    
    Px=$(echo "$R" | cut -d' ' -f1)
    Py=$(echo "$R" | cut -d' ' -f2)
    J=$(echo "$R" | cut -d' ' -f3)
    
    
    S=$(./ecutils -eck -eck-ec-get "$curve_name" -eck-encoding-type "ascii" -eck-decode -eck-decode-px "$Px" -eck-decode-py "$Py" -eck-decode-j "$J")
    echo "  >  ./ecutils -eck -eck-ec-get "$curve_name" -eck-encoding-type "ascii" -eck-decode -eck-decode-px "$Px" -eck-decode-py "$Py" -eck-decode-j "$J""
    
    if [ "$message" != "$S" ]; then
        echo "  >  ECK Error: $message != $S"
        exit 1
    fi
    
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"

echo "  >  Testing ECMO Unicode: ..."
curve_names=("secp384r1" "secp521r1")
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
    
    BOB=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key"
    
    BOBPx=$(echo "$BOB" | cut -d' ' -f1)
    BOBPy=$(echo "$BOB" | cut -d' ' -f2)
    
    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-encrypt -ecmo-encrypt-toshare-public-key-px "$BOBPx" -ecmo-encrypt-toshare-public-key-py "$BOBPy" -ecmo-encrypt-message "$message")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-encrypt -ecmo-encrypt-toshare-public-key-px "$BOBPx" -ecmo-encrypt-toshare-public-key-py "$BOBPy" -ecmo-encrypt-message "$message""
    
    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)
    
    ALI=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key"
    
    ALIPx=$(echo "$ALI" | cut -d' ' -f1)
    ALIPy=$(echo "$ALI" | cut -d' ' -f2)
    
    D=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy""

    if [ "$message" != "$D" ]; then
        echo "  >  ECMO Error: $message != $D"
        exit 1
    fi
    
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"

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
    
    BOB=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-get-public-key"
    
    BOBPx=$(echo "$BOB" | cut -d' ' -f1)
    BOBPy=$(echo "$BOB" | cut -d' ' -f2)
    
    E=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt -ecmo-encrypt-toshare-public-key-px "$BOBPx" -ecmo-encrypt-toshare-public-key-py "$BOBPy" -ecmo-encrypt-message "$message")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-eck-encoding-type "ascii" -ecmo-encrypt -ecmo-encrypt-toshare-public-key-px "$BOBPx" -ecmo-encrypt-toshare-public-key-py "$BOBPy" -ecmo-encrypt-message "$message""
    
    EPx=$(echo "$E" | cut -d' ' -f1)
    EPy=$(echo "$E" | cut -d' ' -f2)
    EJ=$(echo "$E" | cut -d' ' -f3)
    ER=$(echo "$E" | cut -d' ' -f4)
    ES=$(echo "$E" | cut -d' ' -f5)
    
    ALI=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key)
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D" -ecmo-get-public-key"
    
    ALIPx=$(echo "$ALI" | cut -d' ' -f1)
    ALIPy=$(echo "$ALI" | cut -d' ' -f2)
    
    D=$(./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy")
    echo "  >  ./ecutils -ecmo -ecmo-ec-get "$curve_name" -ecmo-private-key "71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4" -ecmo-eck-encoding-type "ascii" -ecmo-decrypt -ecmo-decrypt-px "$EPx" -ecmo-decrypt-py "$EPy" -ecmo-decrypt-j "$EJ" -ecmo-decrypt-r "$ER" -ecmo-decrypt-s "$ES" -ecmo-decrypt-toshare-public-key-px "$ALIPx" -ecmo-decrypt-toshare-public-key-py "$ALIPy""

    if [ "$message" != "$D" ]; then
        echo "  >  ECMO Error: $message != $D"
        exit 1
    fi
    
done
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"

echo "  >  Testing EC Dot: ..."
start_time=$(date +%s%N)
R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "0" -ec-dot-qy "0""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "0" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "D""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "4""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "3" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "4" -ec-dot-qy "F""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "2" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "4" -ec-dot-qy "2""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "4" -ec-dot-py "F" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "D""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "4""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "5" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "7" -ec-dot-qy "0""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "7" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "10""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "1""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "8" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "9" -ec-dot-qy "D""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "4" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "4""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "9" -ec-dot-py "D" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "A" -ec-dot-qy "0""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "A" -ec-dot-py "0" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "10""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "1""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "C" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "D" -ec-dot-qy "9""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "8" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "D" -ec-dot-qy "8""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "D" -ec-dot-py "9" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "E 10" ]; then
    echo "EC Dot Error: $R != E 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "1""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "1" -ec-dot-qx "E" -ec-dot-qy "10""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "0" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "0" -ec-dot-qy "0""

if [ "$R" != "5 4" ]; then
    echo "EC Dot Error: $R != 5 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "4""

if [ "$R" != "4 F" ]; then
    echo "EC Dot Error: $R != 4 F"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "3" -ec-dot-qy "D""

if [ "$R" != "D 9" ]; then
    echo "EC Dot Error: $R != D 9"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "2""

if [ "$R" != "3 D" ]; then
    echo "EC Dot Error: $R != 3 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "F")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "4" -ec-dot-qy "F""

if [ "$R" != "7 0" ]; then
    echo "EC Dot Error: $R != 7 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "4""

if [ "$R" != "D 8" ]; then
    echo "EC Dot Error: $R != D 8"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "5" -ec-dot-qy "D""

if [ "$R" != "0 0" ]; then
    echo "EC Dot Error: $R != 0 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "7" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "7" -ec-dot-qy "0""

if [ "$R" != "4 2" ]; then
    echo "EC Dot Error: $R != 4 2"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "1""

if [ "$R" != "E 1" ]; then
    echo "EC Dot Error: $R != E 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "8" -ec-dot-qy "10""

if [ "$R" != "C 1" ]; then
    echo "EC Dot Error: $R != C 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "4")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "4""

if [ "$R" != "C 10" ]; then
    echo "EC Dot Error: $R != C 10"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "D")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "9" -ec-dot-qy "D""

if [ "$R" != "A 0" ]; then
    echo "EC Dot Error: $R != A 0"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "A" -ec-dot-qy "0")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "A" -ec-dot-qy "0""

if [ "$R" != "9 4" ]; then
    echo "EC Dot Error: $R != 9 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "1""

if [ "$R" != "9 D" ]; then
    echo "EC Dot Error: $R != 9 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "C" -ec-dot-qy "10""

if [ "$R" != "8 1" ]; then
    echo "EC Dot Error: $R != 8 1"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "8")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "8""

if [ "$R" != "3 4" ]; then
    echo "EC Dot Error: $R != 3 4"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "9")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "D" -ec-dot-qy "9""

if [ "$R" != "5 D" ]; then
    echo "EC Dot Error: $R != 5 D"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "1")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "1""
if [ "$R" != "∞" ]; then
    echo "EC Dot Error: $R != ∞"
    exit 1
fi

R=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "10")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-dot -ec-dot-px "E" -ec-dot-py "10" -ec-dot-qx "E" -ec-dot-qy "10""

if [ "$R" != "8 10" ]; then
    echo "EC Dot Error: $R != 8 10"
    exit 1
fi

end_time=$(date +%s%N)

execution_time=$((($end_time - $start_time) / 1000000))

echo "  >  Finished, execution time: ${execution_time} ms"

echo "  >  Testing EC Trapdoor: ..."
 
start_time=$(date +%s%N)

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "0" -ec-trapdoor-gy "0" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "0" -ec-trapdoor-gy "0" -ec-trapdoor-k "2""
if [ "$S" != "∞"  ]; then
    echo "EC Trapdoor Error: $S != ∞"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "3" -ec-trapdoor-gy "4" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "3" -ec-trapdoor-gy "4" -ec-trapdoor-k "2""
if [ "$S" != "9 4" ]; then
    echo "EC Trapdoor Error: $S != 9 4"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "3" -ec-trapdoor-gy "D" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "3" -ec-trapdoor-gy "D" -ec-trapdoor-k "2""
if [ "$S" != "9 D" ]; then
    echo "EC Trapdoor Error: $S != 9 D"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "4" -ec-trapdoor-gy "2" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "4" -ec-trapdoor-gy "2" -ec-trapdoor-k "2""
if [ "$S" != "8 10" ]; then
    echo "EC Trapdoor Error: $S != 8 10"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "4" -ec-trapdoor-gy "F" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "4" -ec-trapdoor-gy "F" -ec-trapdoor-k "2""
if [ "$S" != "8 1" ]; then
    echo "EC Trapdoor Error: $S != 8 1"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "5" -ec-trapdoor-gy "4" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "5" -ec-trapdoor-gy "4" -ec-trapdoor-k "2""
if [ "$S" != "8 10" ]; then
    echo "EC Trapdoor Error: $S != 8 10"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "5" -ec-trapdoor-gy "D" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "5" -ec-trapdoor-gy "D" -ec-trapdoor-k "2""
if [ "$S" != "8 1" ]; then
    echo "EC Trapdoor Error: $S != 8 1"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "7" -ec-trapdoor-gy "0" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "7" -ec-trapdoor-gy "0" -ec-trapdoor-k "2""
if [ "$S" != "∞"  ]; then
    echo "EC Trapdoor Error: $S != ∞"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "8" -ec-trapdoor-gy "1" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "8" -ec-trapdoor-gy "1" -ec-trapdoor-k "2""
if [ "$S" != "9 4" ]; then
    echo "EC Trapdoor Error: $S != 9 4"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "8" -ec-trapdoor-gy "10" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "8" -ec-trapdoor-gy "10" -ec-trapdoor-k "2""
if [ "$S" != "9 D" ]; then
    echo "EC Trapdoor Error: $S != 9 D"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "9" -ec-trapdoor-gy "4" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "9" -ec-trapdoor-gy "4" -ec-trapdoor-k "2""
if [ "$S" != "8 10" ]; then
    echo "EC Trapdoor Error: $S != 8 10"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "9" -ec-trapdoor-gy "D" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "9" -ec-trapdoor-gy "D" -ec-trapdoor-k "2""
if [ "$S" != "8 1" ]; then
    echo "EC Trapdoor Error: $S != 8 1"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "A" -ec-trapdoor-gy "0" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "A" -ec-trapdoor-gy "0" -ec-trapdoor-k "2""
if [ "$S" != "∞"  ]; then
    echo "EC Trapdoor Error: $S != ∞"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "C" -ec-trapdoor-gy "1" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "C" -ec-trapdoor-gy "1" -ec-trapdoor-k "2""
if [ "$S" != "9 4" ]; then
    echo "EC Trapdoor Error: $S != 9 4"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "C" -ec-trapdoor-gy "10" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "C" -ec-trapdoor-gy "10" -ec-trapdoor-k "2""
if [ "$S" != "9 D" ]; then
    echo "EC Trapdoor Error: $S != 9 D"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "D" -ec-trapdoor-gy "8" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "D" -ec-trapdoor-gy "8" -ec-trapdoor-k "2""
if [ "$S" != "9 D" ]; then
    echo "EC Trapdoor Error: $S != 9 D"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "D" -ec-trapdoor-gy "9" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "D" -ec-trapdoor-gy "9" -ec-trapdoor-k "2""
if [ "$S" != "9 4" ]; then
    echo "EC Trapdoor Error: $S != 9 4"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "E" -ec-trapdoor-gy "1" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "E" -ec-trapdoor-gy "1" -ec-trapdoor-k "2""
if [ "$S" != "8 1" ]; then
    echo "EC Trapdoor Error: $S != 8 1"
    exit 1
fi

S=$(./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "E" -ec-trapdoor-gy "10" -ec-trapdoor-k "2")
echo "  >  ./ecutils -ec -ec-define -ec-define-a "2" -ec-define-b "0" -ec-define-p "11" -ec-trapdoor -ec-trapdoor-gx "E" -ec-trapdoor-gy "10" -ec-trapdoor-k "2""
if [ "$S" != "8 10" ]; then
    echo "EC Trapdoor Error: $S != 8 10"
    exit 1
fi
end_time=$(date +%s%N)
execution_time=$((($end_time - $start_time) / 1000000))
echo "  >  Finished, execution time: ${execution_time} ms"
