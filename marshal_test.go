package macaroon_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"

	"gopkg.in/macaroon.v2"
)

func TestMarshalUnmarshalMacaroonV1(t *testing.T) {
	c := qt.New(t)
	testMarshalUnmarshalWithVersion(c, macaroon.V1)
}

func TestMarshalUnmarshalMacaroonV2(t *testing.T) {
	c := qt.New(t)
	testMarshalUnmarshalWithVersion(c, macaroon.V2)
}

func testMarshalUnmarshalWithVersion(c *qt.C, vers macaroon.Version) {
	rootKey := []byte("secret")
	m := MustNew(rootKey, []byte("some id"), "a location", vers)

	// Adding the third party caveat before the first party caveat
	// tests a former bug where the caveat wasn't zeroed
	// before moving to the next caveat.
	err := m.AddThirdPartyCaveat([]byte("shared root key"), []byte("3rd party caveat"), "remote.com")
	c.Assert(err, qt.Equals, nil)

	err = m.AddFirstPartyCaveat([]byte("a caveat"))
	c.Assert(err, qt.Equals, nil)

	b, err := m.MarshalBinary()
	c.Assert(err, qt.Equals, nil)

	var um macaroon.Macaroon
	err = um.UnmarshalBinary(b)
	c.Assert(err, qt.Equals, nil)

	c.Assert(um.Location(), qt.Equals, m.Location())
	c.Assert(string(um.Id()), qt.Equals, string(m.Id()))
	c.Assert(um.Signature(), qt.DeepEquals, m.Signature())
	c.Assert(um.Caveats(), qt.DeepEquals, m.Caveats())
	c.Assert(um.Version(), qt.Equals, vers)
	um.SetVersion(m.Version())
	c.Assert(m, qt.DeepEquals, &um)
}

func TestMarshalBinaryRoundTrip(t *testing.T) {
	c := qt.New(t)
	// This data holds the V2 binary encoding of
	data := []byte(
		"\x02" +
			"\x01\x0ehttp://mybank/" +
			"\x02\x1cwe used our other secret key" +
			"\x00" +
			"\x02\x14account = 3735928559" +
			"\x00" +
			"\x01\x13http://auth.mybank/" +
			"\x02'this was how we remind auth of key/pred" +
			"\x04\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd3\x6e\xc5\x02\xe0\x58\x86\xd1\xf0\x27\x9f\x05\x5f\xa5\x25\x54\xd1\x6d\x16\xc1\xb1\x40\x74\xbb\xb8\x3f\xf0\xfd\xd7\x9d\xc2\xfe\x09\x8f\x0e\xd4\xa2\xb0\x91\x13\x0e\x6b\x5d\xb4\x6a\x20\xa8\x6b" +
			"\x00" +
			"\x00" +
			"\x06\x20\xd2\x7d\xb2\xfd\x1f\x22\x76\x0e\x4c\x3d\xae\x81\x37\xe2\xd8\xfc\x1d\xf6\xc0\x74\x1c\x18\xae\xd4\xb9\x72\x56\xbf\x78\xd1\xf5\x5c",
	)
	var m macaroon.Macaroon
	err := m.UnmarshalBinary(data)
	c.Assert(err, qt.Equals, nil)
	assertLibMacaroonsMacaroon(c, &m)
	c.Assert(m.Version(), qt.Equals, macaroon.V2)

	data1, err := m.MarshalBinary()
	c.Assert(err, qt.Equals, nil)
	c.Assert(data1, qt.DeepEquals, data)
}

func TestBinaryJSONRoundTripV1(t *testing.T) {
	c := qt.New(t)
	testBinaryJSONRoundTrip(c, macaroon.V1)
}

func TestBinaryJSONRoundTripV2(t *testing.T) {
	c := qt.New(t)
	testBinaryJSONRoundTrip(c, macaroon.V2)
}

func testBinaryJSONRoundTrip(c *qt.C, vers macaroon.Version) {
	m1 := MustNew([]byte("rootkey"), []byte("some id"), "a location", vers)
	err := m1.AddFirstPartyCaveat([]byte("a caveat"))
	c.Assert(err, qt.Equals, nil)
	err = m1.AddThirdPartyCaveat([]byte("shared root key"), []byte("3rd party caveat"), "remote.com")
	c.Assert(err, qt.Equals, nil)

	binData1, err := m1.MarshalBinary()
	c.Assert(err, qt.Equals, nil)

	jsonData1, err := json.Marshal(m1)
	c.Assert(err, qt.Equals, nil)

	var m2 *macaroon.Macaroon
	err = json.Unmarshal(jsonData1, &m2)
	c.Assert(err, qt.Equals, nil)

	binData2, err := m2.MarshalBinary()
	c.Assert(err, qt.Equals, nil)

	c.Assert(binData1, qt.DeepEquals, binData2)
}

func TestMarshalUnmarshalSliceV1(t *testing.T) {
	c := qt.New(t)
	testMarshalUnmarshalSliceWithVersion(c, macaroon.V1)
}

func TestMarshalUnmarshalSliceV2(t *testing.T) {
	c := qt.New(t)
	testMarshalUnmarshalSliceWithVersion(c, macaroon.V2)
}

func testMarshalUnmarshalSliceWithVersion(c *qt.C, vers macaroon.Version) {
	rootKey := []byte("secret")
	m1 := MustNew(rootKey, []byte("some id"), "a location", vers)
	m2 := MustNew(rootKey, []byte("some other id"), "another location", vers)

	err := m1.AddFirstPartyCaveat([]byte("a caveat"))
	c.Assert(err, qt.Equals, nil)
	err = m2.AddFirstPartyCaveat([]byte("another caveat"))
	c.Assert(err, qt.Equals, nil)

	macaroons := macaroon.Slice{m1, m2}

	b, err := macaroons.MarshalBinary()
	c.Assert(err, qt.Equals, nil)

	var unmarshaledMacs macaroon.Slice
	err = unmarshaledMacs.UnmarshalBinary(b)
	c.Assert(err, qt.Equals, nil)

	c.Assert(unmarshaledMacs, qt.HasLen, len(macaroons))
	for i, m := range macaroons {
		um := unmarshaledMacs[i]
		c.Assert(um.Location(), qt.Equals, m.Location())
		c.Assert(string(um.Id()), qt.Equals, string(m.Id()))
		c.Assert(um.Signature(), qt.DeepEquals, m.Signature())
		c.Assert(um.Caveats(), qt.DeepEquals, m.Caveats())
		c.Assert(um.Version(), qt.Equals, vers)
		um.SetVersion(m.Version())
	}
	c.Assert(macaroons, qt.DeepEquals, unmarshaledMacs)

	// Check that appending a caveat to the first does not
	// affect the second.
	for i := 0; i < 10; i++ {
		err = unmarshaledMacs[0].AddFirstPartyCaveat([]byte("caveat"))
		c.Assert(err, qt.Equals, nil)
	}
	unmarshaledMacs[1].SetVersion(macaroons[1].Version())
	c.Assert(unmarshaledMacs[1], qt.DeepEquals, macaroons[1])
	c.Assert(err, qt.Equals, nil)
}

func TestSliceRoundTripV1(t *testing.T) {
	c := qt.New(t)
	testSliceRoundTripWithVersion(c, macaroon.V1)
}

func TestSliceRoundTripV2(t *testing.T) {
	c := qt.New(t)
	testSliceRoundTripWithVersion(c, macaroon.V2)
}

func testSliceRoundTripWithVersion(c *qt.C, vers macaroon.Version) {
	rootKey := []byte("secret")
	m1 := MustNew(rootKey, []byte("some id"), "a location", vers)
	m2 := MustNew(rootKey, []byte("some other id"), "another location", vers)

	err := m1.AddFirstPartyCaveat([]byte("a caveat"))
	c.Assert(err, qt.Equals, nil)
	err = m2.AddFirstPartyCaveat([]byte("another caveat"))
	c.Assert(err, qt.Equals, nil)

	macaroons := macaroon.Slice{m1, m2}

	b, err := macaroons.MarshalBinary()
	c.Assert(err, qt.Equals, nil)

	var unmarshaledMacs macaroon.Slice
	err = unmarshaledMacs.UnmarshalBinary(b)
	c.Assert(err, qt.Equals, nil)

	marshaledMacs, err := unmarshaledMacs.MarshalBinary()
	c.Assert(err, qt.Equals, nil)

	c.Assert(b, qt.DeepEquals, marshaledMacs)
}

var base64DecodeTests = []struct {
	about       string
	input       string
	expect      string
	expectError string
}{{
	about:  "empty string",
	input:  "",
	expect: "",
}, {
	about:  "standard encoding, padded",
	input:  "Z29+IQ==",
	expect: "go~!",
}, {
	about:  "URL encoding, padded",
	input:  "Z29-IQ==",
	expect: "go~!",
}, {
	about:  "standard encoding, not padded",
	input:  "Z29+IQ",
	expect: "go~!",
}, {
	about:  "URL encoding, not padded",
	input:  "Z29-IQ",
	expect: "go~!",
}, {
	about:       "standard encoding, too much padding",
	input:       "Z29+IQ===",
	expectError: `illegal base64 data at input byte 8`,
}}

func TestBase64Decode(t *testing.T) {
	c := qt.New(t)
	for i, test := range base64DecodeTests {
		c.Logf("test %d: %s", i, test.about)
		out, err := macaroon.Base64Decode([]byte(test.input))
		if test.expectError != "" {
			c.Assert(err, qt.ErrorMatches, test.expectError)
		} else {
			c.Assert(err, qt.Equals, nil)
			c.Assert(string(out), qt.Equals, test.expect)
		}
	}
}

// makeMigrationTestMacaroons returns two macaroons with different
// root keys, identifiers, locations, caveat chains and versions.
func makeMigrationTestMacaroons(c *qt.C, vers1, vers2 macaroon.Version) (m1, m2 *macaroon.Macaroon) {
	m1 = MustNew([]byte("root key one"), []byte("id one"), "location one", vers1)
	c.Assert(m1.AddFirstPartyCaveat([]byte("caveat one")), qt.IsNil)
	c.Assert(m1.AddFirstPartyCaveat([]byte("caveat two")), qt.IsNil)
	m2 = MustNew([]byte("root key two"), []byte("id two"), "location two", vers2)
	c.Assert(m2.AddFirstPartyCaveat([]byte("another caveat")), qt.IsNil)
	return m1, m2
}

func TestUnmarshalBinaryReplacesPreviousState(t *testing.T) {
	c := qt.New(t)
	for _, vers1 := range jsonTestVersions {
		for _, vers2 := range jsonTestVersions {
			c.Run(fmt.Sprintf("%v_to_%v", vers1, vers2), func(c *qt.C) {
				m1, m2 := makeMigrationTestMacaroons(c, vers1, vers2)
				data1, err := m1.MarshalBinary()
				c.Assert(err, qt.IsNil)
				data2, err := m2.MarshalBinary()
				c.Assert(err, qt.IsNil)

				// Unmarshal the first token, then migrate the same
				// macaroon value to the second token.
				var m macaroon.Macaroon
				c.Assert(m.UnmarshalBinary(data1), qt.IsNil)
				c.Assert(m.UnmarshalBinary(data2), qt.IsNil)

				// The result must be exactly the same as unmarshaling
				// the second token into a fresh macaroon - the version,
				// the caveat chain and the signature must be frozen from
				// the second token, with nothing carried over from the first.
				var fresh macaroon.Macaroon
				c.Assert(fresh.UnmarshalBinary(data2), qt.IsNil)
				c.Assert(m.Version(), qt.Equals, vers2)
				c.Assert(m.Caveats(), qt.HasLen, 1)
				c.Assert(m.Signature(), qt.DeepEquals, fresh.Signature())
				c.Assert(m.Equal(&fresh), qt.Equals, true)
			})
		}
	}
}

func TestUnmarshalJSONReplacesPreviousState(t *testing.T) {
	c := qt.New(t)
	for _, vers1 := range jsonTestVersions {
		for _, vers2 := range jsonTestVersions {
			c.Run(fmt.Sprintf("%v_to_%v", vers1, vers2), func(c *qt.C) {
				m1, m2 := makeMigrationTestMacaroons(c, vers1, vers2)
				data1, err := m1.MarshalJSON()
				c.Assert(err, qt.IsNil)
				data2, err := m2.MarshalJSON()
				c.Assert(err, qt.IsNil)

				var m macaroon.Macaroon
				c.Assert(m.UnmarshalJSON(data1), qt.IsNil)
				c.Assert(m.UnmarshalJSON(data2), qt.IsNil)

				var fresh macaroon.Macaroon
				c.Assert(fresh.UnmarshalJSON(data2), qt.IsNil)
				c.Assert(m.Version(), qt.Equals, vers2)
				c.Assert(m.Caveats(), qt.HasLen, 1)
				c.Assert(m.Signature(), qt.DeepEquals, fresh.Signature())
				c.Assert(m.Equal(&fresh), qt.Equals, true)
			})
		}
	}
}

func TestUnmarshalBinaryFailureLeavesMacaroonUnchanged(t *testing.T) {
	c := qt.New(t)
	for _, vers := range jsonTestVersions {
		c.Run(fmt.Sprintf("%v", vers), func(c *qt.C) {
			m := MustNew([]byte("root key"), []byte("some id"), "a location", vers)
			c.Assert(m.AddFirstPartyCaveat([]byte("a caveat")), qt.IsNil)
			data, err := m.MarshalBinary()
			c.Assert(err, qt.IsNil)

			var um macaroon.Macaroon
			c.Assert(um.UnmarshalBinary(data), qt.IsNil)
			before := um.Clone()

			// A truncated token must fail to unmarshal and must
			// not change the macaroon in any way.
			c.Assert(um.UnmarshalBinary(data[:len(data)-5]), qt.Not(qt.IsNil))
			c.Assert(um.Equal(before), qt.Equals, true)
			c.Assert(um.Version(), qt.Equals, vers)

			// A retry with valid data must still succeed and
			// reproduce the original macaroon exactly.
			c.Assert(um.UnmarshalBinary(data), qt.IsNil)
			c.Assert(um.Equal(m), qt.Equals, true)
		})
	}
}

func TestUnmarshalJSONFailureLeavesMacaroonUnchanged(t *testing.T) {
	c := qt.New(t)
	for _, vers := range jsonTestVersions {
		c.Run(fmt.Sprintf("%v", vers), func(c *qt.C) {
			m := MustNew([]byte("root key"), []byte("some id"), "a location", vers)
			c.Assert(m.AddFirstPartyCaveat([]byte("a caveat")), qt.IsNil)
			data, err := m.MarshalJSON()
			c.Assert(err, qt.IsNil)

			var um macaroon.Macaroon
			c.Assert(um.UnmarshalJSON(data), qt.IsNil)
			before := um.Clone()

			// A V2 token with an invalid signature.
			err = um.UnmarshalJSON([]byte(`{"i": "hello", "s64": "0n2y/R8idg5MPa6BN+LY/B32wHQcGK7UuXJWv3jR9Q"}`))
			c.Assert(err, qt.Not(qt.IsNil))
			c.Assert(um.Equal(before), qt.Equals, true)

			// A V1 token with an invalid signature.
			err = um.UnmarshalJSON([]byte(`{"caveats": [], "location": "x", "identifier": "y", "signature": "zz"}`))
			c.Assert(err, qt.Not(qt.IsNil))
			c.Assert(um.Equal(before), qt.Equals, true)

			// A base64-encoded truncated binary token.
			binData, err := m.MarshalBinary()
			c.Assert(err, qt.IsNil)
			truncated := binData[:len(binData)-5]
			err = um.UnmarshalJSON([]byte(`"` + base64.StdEncoding.EncodeToString(truncated) + `"`))
			c.Assert(err, qt.Not(qt.IsNil))
			c.Assert(um.Equal(before), qt.Equals, true)

			// A retry with valid data must still succeed and
			// reproduce the original macaroon exactly.
			c.Assert(um.UnmarshalJSON(data), qt.IsNil)
			c.Assert(um.Equal(m), qt.Equals, true)
		})
	}
}

func TestSliceUnmarshalBinaryFailureLeavesSliceUnchanged(t *testing.T) {
	c := qt.New(t)
	// Use different versions for the two macaroons - a slice may
	// legitimately contain a mixture of encoding versions.
	m1 := MustNew([]byte("root key"), []byte("id one"), "location one", macaroon.V2)
	c.Assert(m1.AddFirstPartyCaveat([]byte("caveat one")), qt.IsNil)
	m2 := MustNew([]byte("root key"), []byte("id two"), "location two", macaroon.V1)
	c.Assert(m2.AddFirstPartyCaveat([]byte("caveat two")), qt.IsNil)
	s := macaroon.Slice{m1, m2}
	data, err := s.MarshalBinary()
	c.Assert(err, qt.IsNil)

	var us macaroon.Slice
	c.Assert(us.UnmarshalBinary(data), qt.IsNil)
	c.Assert(us, qt.HasLen, 2)

	// Truncate the data so that the second macaroon cannot be
	// parsed. The whole slice must be left unchanged.
	c.Assert(us.UnmarshalBinary(data[:len(data)-5]), qt.Not(qt.IsNil))
	c.Assert(us, qt.HasLen, 2)
	c.Assert(us[0].Equal(m1), qt.Equals, true)
	c.Assert(us[1].Equal(m2), qt.Equals, true)

	// A retry with valid data must still succeed.
	c.Assert(us.UnmarshalBinary(data), qt.IsNil)
	c.Assert(us, qt.HasLen, 2)
	c.Assert(us[0].Equal(m1), qt.Equals, true)
	c.Assert(us[1].Equal(m2), qt.Equals, true)
}

func TestMarshalUnmarshalEmptyCaveats(t *testing.T) {
	c := qt.New(t)
	for _, vers := range jsonTestVersions {
		c.Run(fmt.Sprintf("%v", vers), func(c *qt.C) {
			m := MustNew([]byte("root key"), []byte("some id"), "a location", vers)
			c.Assert(m.Caveats(), qt.HasLen, 0)

			binData, err := m.MarshalBinary()
			c.Assert(err, qt.IsNil)
			var umb macaroon.Macaroon
			c.Assert(umb.UnmarshalBinary(binData), qt.IsNil)
			c.Assert(umb.Version(), qt.Equals, vers)
			c.Assert(umb.Caveats(), qt.HasLen, 0)
			c.Assert(umb.Equal(m), qt.Equals, true)

			// The empty-caveat macaroon must round-trip exactly.
			binData1, err := umb.MarshalBinary()
			c.Assert(err, qt.IsNil)
			c.Assert(binData1, qt.DeepEquals, binData)

			jsonData, err := m.MarshalJSON()
			c.Assert(err, qt.IsNil)
			var umj macaroon.Macaroon
			c.Assert(umj.UnmarshalJSON(jsonData), qt.IsNil)
			c.Assert(umj.Version(), qt.Equals, vers)
			c.Assert(umj.Caveats(), qt.HasLen, 0)
			c.Assert(umj.Equal(m), qt.Equals, true)
		})
	}
}
