package ecdh_test

import (
	"ecutils/internal/ec"
	"ecutils/internal/ecdh"
	"math/big"
	"testing"
)

func TestECDHPublicKey(t *testing.T) {
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
		bob := ecdh.ECDH{
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

func TestECDHToShare(t *testing.T) {
	expectedValues := map[string]struct {
		sharePx, sharePy string
	}{

		"secp192k1": {
			sharePx: "5C947F3D515FDCD56D50971B1E8017E692CAC847A0FB47E0",
			sharePy: "2F4811D9EC890E12785B32A8D8FB037A180D1A479E3E0D33",
		},

		"secp192r1": {
			sharePx: "A143625D454B78C320ADB582B5B5302A6EBBE6A1C40C134C",
			sharePy: "BCA4A114C1099F36AE57D9EBEDB2B6FB7B1A5DF51DB9925D",
		},

		"secp224k1": {
			sharePx: "C1525AB1FD496E5D67BFB2BD8D4B565FFCC8F2BCA9D84708466E09F6",
			sharePy: "F10AD68C263DB20F59311FF2B864CCD7D31C7B0A32E245908352F9A",
		},

		"secp224r1": {
			sharePx: "46451EDC2F368F302FBD7D105BA662D33ACF2BC6C89C5E603D39D4B1",
			sharePy: "A06CCC0D486824270EB8C73695271515B8EB3172B25A61580C97263B",
		},

		"secp256k1": {
			sharePx: "F07EAC9673CD7D31B39686B0B7430F936C1002F1D9D9F7C19307A178134A65E7",
			sharePy: "906C5CA9D05B6881616ED2CB96EBF8F26AEE93B213CF9BD702C830700408F4C9",
		},

		"secp256r1": {
			sharePx: "2DE38E637D7D585E2248C451CB36D4952487CC249BC65440CC38EB3AB6381E6",
			sharePy: "721ECD512B70183B64CE46E6B5923F40F2FDBF655950DC62EA932D600E28D9CE",
		},

		"secp384r1": {
			sharePx: "73AC2BAB063E5847F46F34F37B22A2E01985C75DED5545545002CE6AAB3291D5F5F69D5734182909516CDA096FA059AE",
			sharePy: "C2E63D7FEA89064662571A2C6FA291BC20BE523A6FB4C8B55DD61D9C3143A5A6D0BB8FAC22CF5DBEFF895D7935848E6A",
		},

		"secp521r1": {
			sharePx: "66DD076F9E6B602D7BB12F29EEB58449473D47FB9145BF23378911C674D8A1014B2BDA83D49322DE76D7F1CB9A12CC10FD1F8E6868C33FCD84B7219BA696E0666B",
			sharePy: "104C9CEEFE774752A25108472C5B6F837B96A27CEAA26468752B9C19E3A8D77E8F02FA397677F70469A09A75F0B912B21D4E836638E9FAAD486ED69611915869B6D",
		},
	}
	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	for curveName, expected := range expectedValues {
		curve := ec.Get(curveName)
		alice := ecdh.ECDH{
			Curve:      &curve,
			PrivateKey: alicePrivateKey,
		}
		alicePublicKey := alice.PublicKey()

		bob := ecdh.ECDH{
			Curve:      &curve,
			PrivateKey: bobPrivateKey,
		}
		bobPublicKey := bob.PublicKey()

		aliceSharesWithBob := alice.ToShare(&bobPublicKey)
		bobSharesWithRute := bob.ToShare(&alicePublicKey)

		if aliceSharesWithBob.Px.Cmp(bobSharesWithRute.Px) != 0 || aliceSharesWithBob.Py.Cmp(bobSharesWithRute.Py) != 0 {
			t.Errorf("ToShare expected (%v, %v), got (%v, %v) for curve %s", aliceSharesWithBob.Px, aliceSharesWithBob.Py, bobSharesWithRute.Px, bobSharesWithRute.Py, curveName)
		}

		expectedSharePx := new(big.Int)
		expectedSharePx.SetString(expected.sharePx, 16)

		expectedSharePy := new(big.Int)
		expectedSharePy.SetString(expected.sharePy, 16)

		if aliceSharesWithBob.Px.Cmp(expectedSharePx) != 0 || aliceSharesWithBob.Py.Cmp(expectedSharePy) != 0 {
			t.Errorf("ToShare expected (%v, %v), got (%v, %v) for curve %s", aliceSharesWithBob.Px, aliceSharesWithBob.Py, expectedSharePx, expectedSharePy, curveName)
		}

	}
}
