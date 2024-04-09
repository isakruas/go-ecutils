package ec_test

import (
	"ecutils/internal/ec"
	"math/big"
	"testing"
)

func TestECTrapdoorPanic(t *testing.T) {
	curve := ec.Get("secp192k1")

	K := new(big.Int)
	K.SetString("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A", 16)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()

	curve.Trapdoor(&ec.Point{
		Px: curve.Gx,
		Py: curve.Gy,
	}, K)
}

func TestECIsPointOnCurve(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected a panic, but got none")
		}
	}()

	curve := &ec.EC{
		P:  big.NewInt(13),
		A:  big.NewInt(1),
		B:  big.NewInt(0),
		Gx: big.NewInt(2),
		Gy: big.NewInt(6),
		N:  big.NewInt(0),
		H:  big.NewInt(0),
	}

	P := ec.Point{
		Px: big.NewInt(2),
		Py: big.NewInt(7),
	}

	Q := ec.Point{
		Px: big.NewInt(3),
		Py: big.NewInt(17),
	}

	curve.Dot(P, Q)
}

func TestECPointNotOnInfinity(t *testing.T) {

	curve := &ec.EC{
		P:  big.NewInt(13),
		A:  big.NewInt(1),
		B:  big.NewInt(0),
		Gx: big.NewInt(2),
		Gy: big.NewInt(6),
		N:  big.NewInt(0),
		H:  big.NewInt(0),
	}

	P := ec.Point{
		Px: big.NewInt(2),
		Py: big.NewInt(7),
	}

	Q := ec.Point{
		Px: big.NewInt(3),
		Py: big.NewInt(11),
	}

	R := curve.Dot(P, Q)

	if R.Px.Cmp(big.NewInt(11)) != 0 || R.Py.Cmp(big.NewInt(9)) != 0 {
		t.Errorf("Expected (11, 9), got (%v, %v)", R.Px, R.Py)
	}
}

func TestECPointOnInfinity(t *testing.T) {

	curve := &ec.EC{
		P:  big.NewInt(13),
		A:  big.NewInt(1),
		B:  big.NewInt(0),
		Gx: big.NewInt(2),
		Gy: big.NewInt(6),
		N:  big.NewInt(0),
		H:  big.NewInt(0),
	}

	P := ec.Point{
		Px: big.NewInt(2),
		Py: big.NewInt(7),
	}

	Q := ec.Point{
		Px: big.NewInt(2),
		Py: big.NewInt(6),
	}

	R := curve.Dot(P, Q)

	if R.Px != nil {
		t.Errorf("Expected (nil, nill), got (%v, %v)", R.Px, R.Py)
	}

	P = ec.Point{
		Px: big.NewInt(0),
		Py: big.NewInt(0),
	}

	Q = ec.Point{
		Px: big.NewInt(0),
		Py: big.NewInt(0),
	}

	R = curve.Dot(P, Q)

	if R.Px != nil {
		t.Errorf("Expected (nil, nill), got (%v, %v)", R.Px, R.Py)
	}

	R = curve.Dot(ec.Point{}, Q)

	if R.Px != Q.Px {
		t.Errorf("Expected (nil, nill), got (%v, %v)", Q.Px, Q.Py)
	}

	R = curve.Dot(Q, ec.Point{})

	if R.Px != Q.Px {
		t.Errorf("Expected (nil, nill), got (%v, %v)", Q.Px, Q.Py)
	}

}

func TestECInvalid(t *testing.T) {

	curve := ec.Get("invalid")

	if curve.A != nil {
		t.Errorf("Expected (nil), got (%v)", curve.A)
	}

}

func TestECDot(t *testing.T) {
	expectedValues := map[string]struct {
		DotX, DotY string
	}{
		"secp192k1": {
			DotX: "F091CF6331B1747684F5D2549CD1D4B3A8BED93B94F93CB6",
			DotY: "FD7AF42E1E7565A02E6268661C5E42E603DA2D98A18F2ED5",
		},
		"secp192r1": {
			DotX: "DAFEBF5828783F2AD35534631588A3F629A70FB16982A888",
			DotY: "DD6BDA0D993DA0FA46B27BBC141B868F59331AFA5C7E93AB",
		},
		"secp224k1": {
			DotX: "86C0DEB56AEB9712390999A0232B9BF596B9639FA1CE8CF426749E60",
			DotY: "8F598C954E1085555B474A79906B855C539ED633DBF4A9FA9F06B69A",
		},
		"secp224r1": {
			DotX: "706A46DC76DCB76798E60E6D89474788D16DC18032D268FD1A704FA6",
			DotY: "1C2B76A7BC25E7702A704FA986892849FCA629487ACF3709D2E4E8BB",
		},
		"secp256k1": {
			DotX: "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
			DotY: "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
		},
		"secp256r1": {
			DotX: "7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
			DotY: "7775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
		},
		"secp384r1": {
			DotX: "8D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
			DotY: "8E80F1FA5B1B3CEDB7BFE8DFFD6DBA74B275D875BC6CC43E904E505F256AB4255FFD43E94D39E22D61501E700A940E80",
		},
		"secp521r1": {
			DotX: "433C219024277E7E682FCB288148C282747403279B1CCC06352C6E5505D769BE97B3B204DA6EF55507AA104A3A35C5AF41CF2FA364D60FD967F43E3933BA6D783D",
			DotY: "F4BB8CC7F86DB26700A7F3ECEEEED3F0B5C6B5107C4DA97740AB21A29906C42DBBB3E377DE9F251F6B93937FA99A3248F4EAFCBE95EDC0F4F71BE356D661F41B02",
		},
	}

	for curveName, expected := range expectedValues {
		curve := ec.Get(curveName)

		curvePointP := ec.Point{
			Px: curve.Gx,
			Py: curve.Gy,
		}

		curvePointQ := ec.Point{
			Px: curve.Gx,
			Py: curve.Gy,
		}

		curveDot := curve.Dot(curvePointP, curvePointQ)

		expectedDotX := new(big.Int)
		expectedDotX.SetString(expected.DotX, 16)

		expectedDotY := new(big.Int)
		expectedDotY.SetString(expected.DotY, 16)

		if curveDot.Px.Cmp(expectedDotX) != 0 || curveDot.Py.Cmp(expectedDotY) != 0 {
			t.Errorf("P + Q expected (%v, %v), got (%v, %v) for curve %s", expectedDotX, expectedDotY, curveDot.Px, curveDot.Py, curveName)
		}
	}
}
func TestECTrapdoor(t *testing.T) {

	curve := &ec.EC{
		P:  big.NewInt(17),
		A:  big.NewInt(2),
		B:  big.NewInt(0),
		Gx: big.NewInt(10),
		Gy: big.NewInt(0),
		N:  big.NewInt(16),
		H:  big.NewInt(0),
	}

	P := ec.Point{
		Px: big.NewInt(7),
		Py: big.NewInt(0),
	}

	curveTrapdoor := curve.Trapdoor(&P, big.NewInt(3))

	if curveTrapdoor.Px.Cmp(big.NewInt(7)) != 0 || curveTrapdoor.Py.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("k * G expected (%v, %v), got (%v, %v)", big.NewInt(7), big.NewInt(0), curveTrapdoor.Px, curveTrapdoor.Py)
	}

	expectedValues := map[string]struct {
		TrapdoorX, TrapdoorY string
	}{
		"secp192k1": {
			TrapdoorX: "1AD88667324F81330FD5DF10BE7B8E532FCD5603C93DB78F",
			TrapdoorY: "4BF967179DF5E8CB3D6C32BBB8879E0A9D2E3BA922640846",
		},
		"secp192r1": {
			TrapdoorX: "475D48FA88A9F3B69C4D094B44DBD76618743A4C2D59065D",
			TrapdoorY: "8DE7CFD7030972DD5B90037AEA756C573929BD5DA57C764B",
		},
		"secp224k1": {
			TrapdoorX: "DA98F84A0DA566C96A68B116C04182623B4734EC990DF1F99359EFE9",
			TrapdoorY: "CDBD6DF9D653EA5E2F863FE9821208B7A665740DB7F62049A715EA2",
		},
		"secp224r1": {
			TrapdoorX: "92E41FCB5DB06FC59B562140BA458AFDBEF9789C64343B6078E55326",
			TrapdoorY: "84154AE798A5C4692B213E9218D6FBC8A025C6B2E3D121B38CE29A2F",
		},
		"secp256k1": {
			TrapdoorX: "83D1A3BA3BDD620BC00E5A71284662EA85AB2196BC3863C1BBCF29DB703F5355",
			TrapdoorY: "9953D42C6EDF4C3F1C6545E548E18D7D6713077CEADCF66232B6F3EB2EB72982",
		},
		"secp256r1": {
			TrapdoorX: "4D673B4A07A24A4D3F6F2430253FCD8F16A9E579921A589449136A4CA71A12A9",
			TrapdoorY: "F225A248238DA86CD31037793058C8811143A172CEA544FF6BCCB849890DE7CA",
		},
		"secp384r1": {
			TrapdoorX: "437EFD6951E9B7CAF6FF20BE3F14B9F83D4583C72FDDDFF0A5ECD2FCE632AD669F23195EA19EF05ED17B42C4926705AC",
			TrapdoorY: "4B6BE0D8B1462A811B68089B7DD0526D68D979D6F10830B20595C45BD3AFF48B420781BEF134EF8EA970D3392E1DF548",
		},
		"secp521r1": {
			TrapdoorX: "9111FFEA1524AFE12D6E91ED81C53FCECB62932E5CABCB726B7C40A7B6B864B17BB51F00B137A77A3F165F9BC3A46CE30D33FD1422AF59133E739852B35B85A02F",
			TrapdoorY: "1D9C4A744D93EC5B570CE28B6761F7FE60DFD54F9A72CEEF86D60BCB37DF9DD727C85EDC64B43406849D221C419A1DDD2BDDE7944119958FDE26312FC6B5222DAE9",
		},
	}

	K := new(big.Int)
	K.SetString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9FFFFF425", 16)

	for curveName, expected := range expectedValues {
		curve := ec.Get(curveName)

		curvePointG := ec.Point{
			Px: curve.Gx,
			Py: curve.Gy,
		}

		curveTrapdoor := curve.Trapdoor(&curvePointG, K)

		expectedDotX := new(big.Int)
		expectedDotX.SetString(expected.TrapdoorX, 16)

		expectedDotY := new(big.Int)
		expectedDotY.SetString(expected.TrapdoorY, 16)

		if curveTrapdoor.Px.Cmp(expectedDotX) != 0 || curveTrapdoor.Py.Cmp(expectedDotY) != 0 {
			t.Errorf("k * G expected (%v, %v), got (%v, %v) for curve %s", expectedDotX, expectedDotY, curveTrapdoor.Px, curveTrapdoor.Py, curveName)
		}
	}
}
