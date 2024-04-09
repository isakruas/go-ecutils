package ecdsa_test

import (
	"ecutils/internal/ec"
	"ecutils/internal/ecdsa"
	"math/big"
	"testing"
)

func TestECDSAPublicKey(t *testing.T) {
	expectedValues := map[string]struct {
		PublicKeyPx, PublicKeyPy string
	}{
		"secp192k1": {
			PublicKeyPx: "7867AC344228C91EABACBE0FBB78DA0FE1E5A4D298467811",
			PublicKeyPy: "8C0855236B4F79655A0CBDF18E6125771792524D4DBFD1FE",
		},
		"secp192r1": {
			PublicKeyPx: "A7F7409A7891F7271AC5AB1841754081C51D71ED2D54241A",
			PublicKeyPy: "141E65C9933A8DCF164ACD76F62259AA33C85283D5A00901",
		},
		"secp224k1": {
			PublicKeyPx: "787574F001A570720EA438CE842B049D276DE12ABEF35D0059E471EC",
			PublicKeyPy: "2A198AF582CF049903B7A0FD650292BE71306286C8CEBE036BFB65E8",
		},
		"secp224r1": {
			PublicKeyPx: "4338AC6704FFF1304438269E5050265796D3A7FD8294CAE7F53FAD0C",
			PublicKeyPy: "949FD27DB445D609113867FB824FAEFE50FB9CC3312AA51BCC58226B",
		},
		"secp256k1": {
			PublicKeyPx: "D77D670CAC2AFCE25FE4FE6ADE72A9B2BBFDF837FE8F67C6953597F255B3F2D0",
			PublicKeyPy: "7CA8C02D1AF5AEE64C2F4BC677C1CC8EE81AC47AA0F159B43D709AC515C35629",
		},
		"secp256r1": {
			PublicKeyPx: "D88682A18341486ECBFB9CE7DE94F1ACCB7DDA4EF6EC6C95DDC41826AF70CDD8",
			PublicKeyPy: "C7CD6F1CC4B1F9BBC0D19BB161B00D6A475A0E19747259A48EF18B4CB056B6C7",
		},
		"secp384r1": {
			PublicKeyPx: "6DBE14FF9CA9EB8511632C06CC9E6FCCAE9AC807227CD966E0A00C43821E4F40B2D1B69D9D5A8BE486D9E9AC35ECC684",
			PublicKeyPy: "A492B202490F444FB23291F0767A344F53245D8C9451A4FB9011FE39FB93D3CE5261BC48F53906C86C0ECCA8A49CA2A7",
		},
		"secp521r1": {
			PublicKeyPx: "1C55034D23D7B800E0888F900AA3C00C2695E2881C13EA17897353AD12A93828707ED1C2A5BDB59C746C07D539DC55A9BE9B69624DAD21DAF4259F24C62E58E12B9",
			PublicKeyPy: "1373EDBA1E92E616B12301391302DF25F3F092EE51BDE7A974407781169DBD976DB266CC13388FAE4C856AFEE1BD1A014A778E1CD4C37CB3D58EAD4E18F0125D096",
		},
	}

	privateKey := new(big.Int)
	privateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	for curveName, expected := range expectedValues {
		curve := ec.Get(curveName)
		bob := ecdsa.ECDSA{
			Curve:      &curve,
			PrivateKey: privateKey,
		}

		expectedPublicKeyPx := new(big.Int)
		expectedPublicKeyPx.SetString(expected.PublicKeyPx, 16)

		expectedPublicKeyPy := new(big.Int)
		expectedPublicKeyPy.SetString(expected.PublicKeyPy, 16)

		publicKey := bob.PublicKey()

		if publicKey.Px.Cmp(expectedPublicKeyPx) != 0 || publicKey.Py.Cmp(expectedPublicKeyPy) != 0 {
			t.Errorf("PublicKey expected (%v, %v), got (%v, %v) for curve %s", expectedPublicKeyPx, expectedPublicKeyPy, publicKey.Px, publicKey.Py, curveName)
		}
	}
}

func TestECDSASignatureAndVerifySignature(t *testing.T) {
	curves := []string{"secp192k1", "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1"}

	privateKey := new(big.Int)
	privateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	message := new(big.Int)
	message.SetString("2F4811D9EC890E12785B32A8D8FB037A180D1A479E3E0D33", 16)

	for _, curveName := range curves {
		curve := ec.Get(curveName)

		bob := ecdsa.ECDSA{
			Curve:      &curve,
			PrivateKey: privateKey,
		}
		bobPublicKey := bob.PublicKey()

		r, s := bob.Signature(message)

		for !bob.VerifySignature(message, r, s, &bobPublicKey) {
			t.Errorf("Invalid signature")
		}
	}
}

func TestECDSAInvaidSignature(t *testing.T) {

	curve := ec.Get("secp192k1")

	privateKey := new(big.Int)
	privateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	message := new(big.Int)
	message.SetString("2F4811D9EC890E12785B32A8D8FB037A180D1A479E3E0D33", 16)

	bob := ecdsa.ECDSA{
		Curve:      &curve,
		PrivateKey: privateKey,
	}
	bobPublicKey := bob.PublicKey()

	r, s := bob.Signature(message)

	for bob.VerifySignature(message, s, r, &bobPublicKey) {
		t.Errorf("Expected invalid signature")
	}

}
