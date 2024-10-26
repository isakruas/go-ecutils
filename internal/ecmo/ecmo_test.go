package ecmo_test

import (
	"crypto/rand"
	"go-ecutils/internal/ec"
	"go-ecutils/internal/ecmo"
	"math/big"
	"testing"
)

func TestECMOPublicKey(t *testing.T) {
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
		bob := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      privateKey,
			ECKEncodingType: "unicode",
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

func generateRandomASCIIString(length int) (string, error) {
	const asciiPrintable = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	var result []byte

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(asciiPrintable))))
		if err != nil {
			return "", err
		}
		randomChar := asciiPrintable[randomIndex.Int64()]
		result = append(result, randomChar)
	}

	return string(result), nil
}

func generateRandomUnicodeString(length int) (string, error) {
	const unicodePrintable = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" +
		" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\t\n\r\x0b\x0c"
	var result []rune

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(unicodePrintable))))
		if err != nil {
			return "", err
		}
		randomChar := rune(unicodePrintable[randomIndex.Int64()])
		result = append(result, randomChar)
	}

	return string(result), nil
}

func TestECMOEncryptAndDecryptUnicode(t *testing.T) {

	curves := []string{"secp384r1", "secp521r1"}

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	for _, curveName := range curves {
		curve := ec.Get(curveName)

		alice := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      alicePrivateKey,
			ECKEncodingType: "unicode",
		}
		alicePublicKey := alice.PublicKey()

		bob := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      bobPrivateKey,
			ECKEncodingType: "unicode",
		}
		bobPublicKey := bob.PublicKey()

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomASCIIString(23)

			P, j, r, s := alice.Encrypt(randomString)

			P, j, r, s = bob.Encrypt2(P, j, r, s, &alicePublicKey)

			P, j, r, s = alice.Decrypt(P, j, r, s, &bobPublicKey)

			decrypt := bob.Decrypt2(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomUnicodeString(23)

			P, j, r, s := alice.Encrypt(randomString)

			P, j, r, s = bob.Encrypt2(P, j, r, s, &alicePublicKey)

			P, j, r, s = alice.Decrypt(P, j, r, s, &bobPublicKey)

			decrypt := bob.Decrypt2(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}
	}
}

func TestECMOEncryptAndDecryptASCII(t *testing.T) {

	curves := []string{"secp192k1", "secp192r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1"}

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	for _, curveName := range curves {
		curve := ec.Get(curveName)

		alice := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      alicePrivateKey,
			ECKEncodingType: "ascii",
		}
		alicePublicKey := alice.PublicKey()

		bob := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      bobPrivateKey,
			ECKEncodingType: "ascii",
		}
		bobPublicKey := bob.PublicKey()

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomASCIIString(23)

			P, j, r, s := alice.Encrypt(randomString)

			P, j, r, s = bob.Encrypt2(P, j, r, s, &alicePublicKey)

			P, j, r, s = alice.Decrypt(P, j, r, s, &bobPublicKey)

			decrypt := bob.Decrypt2(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomUnicodeString(23)

			P, j, r, s := alice.Encrypt(randomString)

			P, j, r, s = bob.Encrypt2(P, j, r, s, &alicePublicKey)

			P, j, r, s = alice.Decrypt(P, j, r, s, &bobPublicKey)

			decrypt := bob.Decrypt2(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}
	}
}

func TestECMOEncrypt2Invalid(t *testing.T) {

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	curve := ec.Get("secp192k1")

	alice := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      alicePrivateKey,
		ECKEncodingType: "unicode",
	}
	alicePublicKey := alice.PublicKey()

	bob := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      bobPrivateKey,
		ECKEncodingType: "unicode",
	}

	randomString, _ := generateRandomUnicodeString(23)

	P, j, r, s := alice.Encrypt(randomString)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()

	bob.Encrypt2(P, j, s, r, &alicePublicKey)
}

func TestECMODecryptInvalid(t *testing.T) {

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	curve := ec.Get("secp192k1")

	alice := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      alicePrivateKey,
		ECKEncodingType: "unicode",
	}
	alicePublicKey := alice.PublicKey()

	bob := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      bobPrivateKey,
		ECKEncodingType: "unicode",
	}
	bobPublicKey := bob.PublicKey()

	randomString, _ := generateRandomUnicodeString(23)

	P, j, r, s := alice.Encrypt(randomString)

	P, j, r, s = bob.Encrypt2(P, j, r, s, &alicePublicKey)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()

	alice.Decrypt(P, j, s, r, &bobPublicKey)
}

func TestECMODecrypt2Invalid(t *testing.T) {

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	curve := ec.Get("secp192k1")

	alice := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      alicePrivateKey,
		ECKEncodingType: "unicode",
	}
	alicePublicKey := alice.PublicKey()

	bob := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      bobPrivateKey,
		ECKEncodingType: "unicode",
	}
	bobPublicKey := bob.PublicKey()

	randomString, _ := generateRandomUnicodeString(23)

	P, j, r, s := alice.Encrypt(randomString)

	P, j, r, s = bob.Encrypt2(P, j, r, s, &alicePublicKey)

	P, j, r, s = alice.Decrypt(P, j, r, s, &bobPublicKey)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()

	bob.Decrypt2(P, j, s, r, &alicePublicKey)
}

/*
func TestECMOEncryptAndDecryptUnicode(t *testing.T) {

	curves := []string{"secp384r1", "secp521r1"}

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	for _, curveName := range curves {
		curve := ec.Get(curveName)

		alice := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      alicePrivateKey,
			ECKEncodingType: "unicode",
		}
		alicePublicKey := alice.PublicKey()

		bob := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      bobPrivateKey,
			ECKEncodingType: "unicode",
		}
		bobPublicKey := bob.PublicKey()

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomASCIIString(23)

			P, j, r, s := alice.Encrypt(randomString, &bobPublicKey)

			decrypt := bob.Decrypt(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomUnicodeString(23)

			P, j, r, s := alice.Encrypt(randomString, &bobPublicKey)

			decrypt := bob.Decrypt(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}
	}
}

func TestECMOEncryptAndDecryptASCII(t *testing.T) {

	curves := []string{"secp192k1", "secp192r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1"}

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	for _, curveName := range curves {
		curve := ec.Get(curveName)

		alice := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      alicePrivateKey,
			ECKEncodingType: "ascii",
		}
		alicePublicKey := alice.PublicKey()

		bob := ecmo.ECMO{
			Curve:           &curve,
			PrivateKey:      bobPrivateKey,
			ECKEncodingType: "ascii",
		}
		bobPublicKey := bob.PublicKey()

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomASCIIString(23)

			P, j, r, s := alice.Encrypt(randomString, &bobPublicKey)

			decrypt := bob.Decrypt(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}

		for i := 0; i < 10; i++ {
			randomString, _ := generateRandomUnicodeString(23)

			P, j, r, s := alice.Encrypt(randomString, &bobPublicKey)

			decrypt := bob.Decrypt(P, j, r, s, &alicePublicKey)

			if decrypt != randomString {
				t.Errorf("Decrypt expected (%v), got (%v) for curve %s", "ecutils", decrypt, curveName)
			}
		}
	}
}

func TestECMODecryptInvalid(t *testing.T) {

	alicePrivateKey := new(big.Int)
	alicePrivateKey.SetString("DDC96AD92BFBD123D6DFDD0AF1F989CF87F1A1D5D083A30D", 16)

	bobPrivateKey := new(big.Int)
	bobPrivateKey.SetString("71288A9023BD17824F62C46172BC3B3802A7CF288B069FA4", 16)

	curve := ec.Get("secp192k1")

	alice := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      alicePrivateKey,
		ECKEncodingType: "unicode",
	}
	alicePublicKey := alice.PublicKey()

	bob := ecmo.ECMO{
		Curve:           &curve,
		PrivateKey:      bobPrivateKey,
		ECKEncodingType: "unicode",
	}
	bobPublicKey := bob.PublicKey()

	randomString, _ := generateRandomUnicodeString(23)

	P, j, r, s := alice.Encrypt(randomString, &bobPublicKey)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()

	bob.Decrypt(P, j, s, r, &alicePublicKey)
}
*/
