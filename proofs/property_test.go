package proofs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFieldTags(t *testing.T) {

	_, _, err := ExtractFieldTags("a,b,c")
	assert.EqualError(t, err, "not enough elements in protobuf tag list")

	_, _, err = ExtractFieldTags("a,b,c,d")
	assert.EqualError(t, err, "error parsing ordinal tag: strconv.ParseUint: parsing \"b\": invalid syntax")

	_, _, err = ExtractFieldTags("a,42,c,d")
	assert.EqualError(t, err, "error parsing protobuf field name: \"d\" does not begin with \"name=\"")

	name, num, err := ExtractFieldTags("a,42,c,name=d")
	assert.NoError(t, err)
	assert.Equal(t, name, "d")
	assert.Equal(t, num, FieldNum(42))
}

func TestAsBytes_ReadableName(t *testing.T) {
	assert.Equal(t, []byte{65, 66, 67, 68, 69}, AsBytes(ReadableName("ABCDE")))
}

func TestAsBytes_CompactName(t *testing.T) {
	assert.Equal(t,
		[]byte{
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 0, 0, 0, 0, 0, 255,
			0, 0, 0, 0, 0, 0, 1, 0,
			0, 0, 0, 0, 0, 1, 0, 0,
			0, 0, 0, 0, 0, 0, 255, 255,
		},
		AsBytes(CompactName(1, 255, 256, 256*256, 256*256-1)),
	)
}

func TestKeyToReadable(t *testing.T) {
	s, err := keyToReadable("key")
	assert.NoError(t, err)
	assert.Equal(t, "key", s)

	s, err = keyToReadable(42)
	assert.NoError(t, err)
	assert.Equal(t, "42", s)

	s, err = keyToReadable([]byte{0x2f, 0xa2, 0x93})
	assert.NoError(t, err)
	assert.Equal(t, "0x2fa293", s)

	s, err = keyToReadable(`foo[bar].foo\bar`)
	assert.NoError(t, err)
	assert.Equal(t, `foo\[bar\]\.foo\\bar`, s)
}
