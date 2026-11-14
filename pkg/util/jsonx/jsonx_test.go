package jsonx

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type sampleStruct struct {
	Name  string     `json:"name"`
	Count int        `json:"count"`
	Raw   RawMessage `json:"raw,omitempty"`
}

func TestMarshalUnmarshalAndOptions(t *testing.T) {
	require := require.New(t)

	in := sampleStruct{
		Name:  "demo",
		Count: 42,
		Raw:   RawMessage(`{"nested":true}`),
	}

	b, err := Marshal(in)
	require.NoError(err)
	require.JSONEq(`{"name":"demo","count":42,"raw":{"nested":true}}`, string(b))

	indented, err := MarshalIndent(in, "", "  ")
	require.NoError(err)
	require.Contains(string(indented), "\n  \"name\": \"demo\"")

	var out sampleStruct
	require.NoError(Unmarshal(b, &out))
	require.Equal(in.Name, out.Name)
	require.Equal(in.Count, out.Count)
	require.JSONEq(`{"nested":true}`, string(out.Raw))

	// Unknown fields allowed when RejectUnknownMembers is false
	withUnknown := []byte(`{"name":"demo","count":7,"extra":"ignored"}`)
	var outAllowed sampleStruct
	require.NoError(UnmarshalWithOptions(withUnknown, &outAllowed, DecodeOptions{RejectUnknownMembers: false}))
	require.Equal("demo", outAllowed.Name)
	require.Equal(7, outAllowed.Count)

	// Unknown fields rejected when RejectUnknownMembers is true
	var outStrict sampleStruct
	err = UnmarshalWithOptions(withUnknown, &outStrict, DecodeOptions{RejectUnknownMembers: true})
	require.ErrorContains(err, "unknown field")
}

func TestRawMessageNilAndNonNil(t *testing.T) {
	require := require.New(t)

	var nilRaw RawMessage
	b, err := nilRaw.MarshalJSON()
	require.NoError(err)
	require.Equal("null", string(b))

	var nilPtr *RawMessage
	err = nilPtr.UnmarshalJSON([]byte(`"hello"`))
	require.ErrorContains(err, "UnmarshalJSON on nil pointer")

	var m RawMessage
	require.NoError(m.UnmarshalJSON([]byte(`{"a":1}`)))
	out, err := m.MarshalJSON()
	require.NoError(err)
	require.Equal(`{"a":1}`, string(out))
}
