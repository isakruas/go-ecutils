package eck_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/isakruas/go-ecutils/pkg/ec"
	"github.com/isakruas/go-ecutils/pkg/eck"
)

func TestECKEncodeDefault(t *testing.T) {
	expectedValues := map[string]struct {
		encodePx string
		encodePy string
		encodeJ  *big.Int
	}{
		"secp192k1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "F30F2D8396CCEDC9BC55D8FB55F48544E8815877DC579BD2",
			encodeJ:  big.NewInt(2),
		},
		"secp192r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "5956060F6EC280C0EABDA6DAFBC2343F50C9ACEA54BCEED2",
			encodeJ:  big.NewInt(0),
		},
		"secp224k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp224r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp256k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1B4F7CBBF9E9F215C63B1580DBFF007A2E7DEDD7E6C7BEE9DA543FE8AE7397EB",
			encodeJ:  big.NewInt(0),
		},
		"secp256r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "2C0DE0C1FCF4032AD269B416CA3F4F093743366873F49EDE1C26EA0DD987FD6C",
			encodeJ:  big.NewInt(2),
		},
		"secp384r1": {
			encodePx: "2CEC2A3029042D502DB426AC2777",
			encodePy: "30656F493ABC38FA5D198B4E397D087486153EB452DCC81202D9C2170B97A01DEBC6EE135E1FBF00ABC92E0011469596",
			encodeJ:  big.NewInt(3),
		},
		"secp521r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "1D85AFC29859AFB5F1E6AC58E02A4AA857041DB5573B0E04571B41D7D0577541C41B3622A7B1B7B812950788914D4569D810A66D642D1203489F24310BB4A54C5B6",
			encodeJ:  big.NewInt(2),
		},
	}
	message := "ecutils"
	for curveName, expected := range expectedValues {
		curve := ec.Get(curveName)
		eck := eck.ECK{
			Curve: &curve,
		}

		P, j := eck.Encode(message)

		if j.Cmp(expected.encodeJ) != 0 {
			t.Errorf("j expected (%v), got (%v) for curve %s", expected.encodeJ, j, curveName)
		}

		expectedEncodePx := new(big.Int)
		expectedEncodePx.SetString(expected.encodePx, 16)

		expectedEncodePy := new(big.Int)
		expectedEncodePy.SetString(expected.encodePy, 16)

		if P.Px.Cmp(expectedEncodePx) != 0 || P.Py.Cmp(expectedEncodePy) != 0 {
			t.Errorf("P expected (%v, %v), got (%v, %v) for curve %s", expectedEncodePx, expectedEncodePy, P.Px, P.Py, curveName)
		}
	}
}

func TestECKDecodeDefault(t *testing.T) {
	encodes := map[string]struct {
		encodePx string
		encodePy string
		encodeJ  *big.Int
	}{
		"secp192k1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "F30F2D8396CCEDC9BC55D8FB55F48544E8815877DC579BD2",
			encodeJ:  big.NewInt(2),
		},
		"secp192r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "5956060F6EC280C0EABDA6DAFBC2343F50C9ACEA54BCEED2",
			encodeJ:  big.NewInt(0),
		},
		"secp224k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp224r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp256k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1B4F7CBBF9E9F215C63B1580DBFF007A2E7DEDD7E6C7BEE9DA543FE8AE7397EB",
			encodeJ:  big.NewInt(0),
		},
		"secp256r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "2C0DE0C1FCF4032AD269B416CA3F4F093743366873F49EDE1C26EA0DD987FD6C",
			encodeJ:  big.NewInt(2),
		},
		"secp384r1": {
			encodePx: "2CEC2A3029042D502DB426AC2777",
			encodePy: "30656F493ABC38FA5D198B4E397D087486153EB452DCC81202D9C2170B97A01DEBC6EE135E1FBF00ABC92E0011469596",
			encodeJ:  big.NewInt(3),
		},
		"secp521r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "1D85AFC29859AFB5F1E6AC58E02A4AA857041DB5573B0E04571B41D7D0577541C41B3622A7B1B7B812950788914D4569D810A66D642D1203489F24310BB4A54C5B6",
			encodeJ:  big.NewInt(2),
		},
	}

	for curveName, encode := range encodes {
		curve := ec.Get(curveName)

		eck := eck.ECK{
			Curve: &curve,
		}

		encodePx := new(big.Int)
		encodePx.SetString(encode.encodePx, 16)

		encodePy := new(big.Int)
		encodePy.SetString(encode.encodePy, 16)

		P := ec.Point{
			Px: encodePx,
			Py: encodePy,
		}

		decode := eck.Decode(&P, encode.encodeJ)
		if decode != "ecutils" {
			t.Errorf("Decode expected (%v), got (%v) for curve %s", "ecutils", decode, curveName)
		}
	}
}

func TestECKEncodeUnicode(t *testing.T) {
	expectedValues := map[string]struct {
		encodePx string
		encodePy string
		encodeJ  *big.Int
	}{
		"secp192k1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "F30F2D8396CCEDC9BC55D8FB55F48544E8815877DC579BD2",
			encodeJ:  big.NewInt(2),
		},
		"secp192r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "5956060F6EC280C0EABDA6DAFBC2343F50C9ACEA54BCEED2",
			encodeJ:  big.NewInt(0),
		},
		"secp224k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp224r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp256k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1B4F7CBBF9E9F215C63B1580DBFF007A2E7DEDD7E6C7BEE9DA543FE8AE7397EB",
			encodeJ:  big.NewInt(0),
		},
		"secp256r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "2C0DE0C1FCF4032AD269B416CA3F4F093743366873F49EDE1C26EA0DD987FD6C",
			encodeJ:  big.NewInt(2),
		},
		"secp384r1": {
			encodePx: "2CEC2A3029042D502DB426AC2777",
			encodePy: "30656F493ABC38FA5D198B4E397D087486153EB452DCC81202D9C2170B97A01DEBC6EE135E1FBF00ABC92E0011469596",
			encodeJ:  big.NewInt(3),
		},
		"secp521r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "1D85AFC29859AFB5F1E6AC58E02A4AA857041DB5573B0E04571B41D7D0577541C41B3622A7B1B7B812950788914D4569D810A66D642D1203489F24310BB4A54C5B6",
			encodeJ:  big.NewInt(2),
		},
	}
	message := "ecutils"
	for curveName, expected := range expectedValues {
		curve := ec.Get(curveName)
		eck := eck.ECK{
			Curve:        &curve,
			EncodingType: "unicode",
		}

		P, j := eck.Encode(message)

		if j.Cmp(expected.encodeJ) != 0 {
			t.Errorf("j expected (%v), got (%v) for curve %s", expected.encodeJ, j, curveName)
		}

		expectedEncodePx := new(big.Int)
		expectedEncodePx.SetString(expected.encodePx, 16)

		expectedEncodePy := new(big.Int)
		expectedEncodePy.SetString(expected.encodePy, 16)

		if P.Px.Cmp(expectedEncodePx) != 0 || P.Py.Cmp(expectedEncodePy) != 0 {
			t.Errorf("P expected (%v, %v), got (%v, %v) for curve %s", expectedEncodePx, expectedEncodePy, P.Px, P.Py, curveName)
		}
	}
}

func TestECKDecodeUnicode(t *testing.T) {
	encodes := map[string]struct {
		encodePx string
		encodePy string
		encodeJ  *big.Int
	}{
		"secp192k1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "F30F2D8396CCEDC9BC55D8FB55F48544E8815877DC579BD2",
			encodeJ:  big.NewInt(2),
		},
		"secp192r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "5956060F6EC280C0EABDA6DAFBC2343F50C9ACEA54BCEED2",
			encodeJ:  big.NewInt(0),
		},
		"secp224k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp224r1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp256k1": {
			encodePx: "2CEC2A3029042D502DB426AC2774",
			encodePy: "1B4F7CBBF9E9F215C63B1580DBFF007A2E7DEDD7E6C7BEE9DA543FE8AE7397EB",
			encodeJ:  big.NewInt(0),
		},
		"secp256r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "2C0DE0C1FCF4032AD269B416CA3F4F093743366873F49EDE1C26EA0DD987FD6C",
			encodeJ:  big.NewInt(2),
		},
		"secp384r1": {
			encodePx: "2CEC2A3029042D502DB426AC2777",
			encodePy: "30656F493ABC38FA5D198B4E397D087486153EB452DCC81202D9C2170B97A01DEBC6EE135E1FBF00ABC92E0011469596",
			encodeJ:  big.NewInt(3),
		},
		"secp521r1": {
			encodePx: "2CEC2A3029042D502DB426AC2776",
			encodePy: "1D85AFC29859AFB5F1E6AC58E02A4AA857041DB5573B0E04571B41D7D0577541C41B3622A7B1B7B812950788914D4569D810A66D642D1203489F24310BB4A54C5B6",
			encodeJ:  big.NewInt(2),
		},
	}

	for curveName, encode := range encodes {
		curve := ec.Get(curveName)

		eck := eck.ECK{
			Curve:        &curve,
			EncodingType: "unicode",
		}

		encodePx := new(big.Int)
		encodePx.SetString(encode.encodePx, 16)

		encodePy := new(big.Int)
		encodePy.SetString(encode.encodePy, 16)

		P := ec.Point{
			Px: encodePx,
			Py: encodePy,
		}

		decode := eck.Decode(&P, encode.encodeJ)
		if decode != "ecutils" {
			t.Errorf("Decode expected (%v), got (%v) for curve %s", "ecutils", decode, curveName)
		}
	}
}

func TestECKEncodeASCII(t *testing.T) {
	expectedValues := map[string]struct {
		encodePx string
		encodePy string
		encodeJ  *big.Int
	}{
		"secp192k1": {
			encodePx: "2D1659317DDAD378",
			encodePy: "1EF67CEDBE05CFFBC27F06F1E80DBA8004BFF44137E32DD6",
			encodeJ:  big.NewInt(4),
		},
		"secp192r1": {
			encodePx: "2D1659317DDAD376",
			encodePy: "FBB63C4DE56D6802AD36B2B24808117A09D1B3760E2B9843",
			encodeJ:  big.NewInt(2),
		},
		"secp224k1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp224r1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000",
			encodeJ:  big.NewInt(0),
		},
		"secp256k1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "6E52C90861B04533AEE4E78715B82E1CDDF2AB921DA207093D5E99C626C1E992",
			encodeJ:  big.NewInt(0),
		},
		"secp256r1": {
			encodePx: "2D1659317DDAD377",
			encodePy: "4C7A9EF0201E2EC77E69543D86AC9E5AABAC40A469EDF900EECDA8C42982986A",
			encodeJ:  big.NewInt(3),
		},
		"secp384r1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "268B21D9EE2431F486C122151020D9ADA51DCF2E19FF5883BBA2B2202B9BF114D4CC917686AA120A2E807159B7AE1F6B",
			encodeJ:  big.NewInt(0),
		},
		"secp521r1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "1E00B92CD80327F697F27B6A3C59256CBA9253F522B62F8B3A7D43E3C0BC2183333783ECBDC8EA6EBD2516561E8E4B57984401A5F9ACBE0886AC646B2FB0B059FD7",
			encodeJ:  big.NewInt(0),
		},
	}
	message := "ecutils"
	for curveName, expected := range expectedValues {
		curve := ec.Get(curveName)
		eck := eck.ECK{
			Curve:        &curve,
			EncodingType: "ascii",
		}

		P, j := eck.Encode(message)

		if j.Cmp(expected.encodeJ) != 0 {
			t.Errorf("j expected (%v), got (%v) for curve %s", expected.encodeJ, j, curveName)
		}

		expectedEncodePx := new(big.Int)
		expectedEncodePx.SetString(expected.encodePx, 16)

		expectedEncodePy := new(big.Int)
		expectedEncodePy.SetString(expected.encodePy, 16)

		if P.Px.Cmp(expectedEncodePx) != 0 || P.Py.Cmp(expectedEncodePy) != 0 {
			t.Errorf("P expected (%v, %v), got (%v, %v) for curve %s", expectedEncodePx, expectedEncodePy, P.Px, P.Py, curveName)
		}
	}
}

func TestECKDecodeASCII(t *testing.T) {
	encodes := map[string]struct {
		encodePx string
		encodePy string
		encodeJ  *big.Int
	}{
		"secp192k1": {
			encodePx: "2D1659317DDAD378",
			encodePy: "1EF67CEDBE05CFFBC27F06F1E80DBA8004BFF44137E32DD6",
			encodeJ:  big.NewInt(4),
		},
		"secp192r1": {
			encodePx: "2D1659317DDAD376",
			encodePy: "FBB63C4DE56D6802AD36B2B24808117A09D1B3760E2B9843",
			encodeJ:  big.NewInt(2),
		},
		"secp224k1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "1",
			encodeJ:  big.NewInt(0),
		},
		"secp224r1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000",
			encodeJ:  big.NewInt(0),
		},
		"secp256k1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "6E52C90861B04533AEE4E78715B82E1CDDF2AB921DA207093D5E99C626C1E992",
			encodeJ:  big.NewInt(0),
		},
		"secp256r1": {
			encodePx: "2D1659317DDAD377",
			encodePy: "4C7A9EF0201E2EC77E69543D86AC9E5AABAC40A469EDF900EECDA8C42982986A",
			encodeJ:  big.NewInt(3),
		},
		"secp384r1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "268B21D9EE2431F486C122151020D9ADA51DCF2E19FF5883BBA2B2202B9BF114D4CC917686AA120A2E807159B7AE1F6B",
			encodeJ:  big.NewInt(0),
		},
		"secp521r1": {
			encodePx: "2D1659317DDAD374",
			encodePy: "1E00B92CD80327F697F27B6A3C59256CBA9253F522B62F8B3A7D43E3C0BC2183333783ECBDC8EA6EBD2516561E8E4B57984401A5F9ACBE0886AC646B2FB0B059FD7",
			encodeJ:  big.NewInt(0),
		},
	}

	for curveName, encode := range encodes {
		curve := ec.Get(curveName)

		eck := eck.ECK{
			Curve:        &curve,
			EncodingType: "ascii",
		}

		encodePx := new(big.Int)
		encodePx.SetString(encode.encodePx, 16)

		encodePy := new(big.Int)
		encodePy.SetString(encode.encodePy, 16)

		P := ec.Point{
			Px: encodePx,
			Py: encodePy,
		}

		decode := eck.Decode(&P, encode.encodeJ)
		if decode != "ecutils" {
			t.Errorf("Decode expected (%v), got (%v) for curve %s", "ecutils", decode, curveName)
		}
	}
}

func TestECKEncodeInvalidEncodingType(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()

	curve := ec.Get("secp192k1")
	eck := eck.ECK{
		Curve:        &curve,
		EncodingType: "none",
	}

	P, j := eck.Encode("message")
	fmt.Printf("%v %v", P, j)
}
func TestECKDecodeInvalidEncodingType(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()
	curve := ec.Get("secp192k1")

	eck := eck.ECK{
		Curve:        &curve,
		EncodingType: "none",
	}

	encodePx := new(big.Int)
	encodePx.SetString("2D1659317DDAD378", 16)

	encodePy := new(big.Int)
	encodePy.SetString("1EF67CEDBE05CFFBC27F06F1E80DBA8004BFF44137E32DD6", 16)

	encodeJ := big.NewInt(4)

	P := ec.Point{
		Px: encodePx,
		Py: encodePy,
	}

	decode := eck.Decode(&P, encodeJ)

	fmt.Print(decode)
}
