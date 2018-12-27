package proofs

import (
	"fmt"
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
	assert.Equal(t, "d", name)
	assert.Equal(t, FieldNum(42), num)
}

func TestPropertyName(t *testing.T) {
	baseProp := NewProperty("base", 42)
	assert.Equal(t, "base", baseProp.ReadableName())
	assert.Equal(t, []FieldNum{42}, baseProp.CompactName())

	fieldProp := baseProp.FieldProp("field", 43)
	assert.Equal(t, "base.field", fieldProp.ReadableName())
	assert.Equal(t, []FieldNum{42, 43}, fieldProp.CompactName())

	sliceElemProp := baseProp.SliceElemProp(5)
	assert.Equal(t, "base[5]", sliceElemProp.ReadableName())
	assert.Equal(t, []FieldNum{42, 5}, sliceElemProp.CompactName())

	mapElemProp, err := baseProp.MapElemProp(fmt.Errorf("not a valid key type"), 32)
	assert.Error(t, err)

	mapElemProp, err = baseProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, "base[key]", mapElemProp.ReadableName())
	// TODO assert.Equal(t, []FieldNum{42, "key"}, mapElemProp.CompactName())

	lengthProp := baseProp.LengthProp()
	assert.Equal(t, "base.length", lengthProp.ReadableName())
	assert.Equal(t, []FieldNum{42}, lengthProp.CompactName())
}

func TestFieldPropFromTag(t *testing.T) {
	baseProp := NewProperty("base", 42)

	prop, err := baseProp.FieldPropFromTag("bad proto tags")
	assert.Error(t, err)

	prop, err = baseProp.FieldPropFromTag("a,42,c,name=d")
	assert.NoError(t, err)
	assert.Equal(t, baseProp.FieldProp("d", 42), prop)
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

	s, err = keyToReadable(true)
	assert.NoError(t, err)
	assert.Equal(t, "true", s)

	s, err = keyToReadable(int(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(int8(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(int16(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(int32(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(int64(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(uint(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(uint8(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(uint16(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(uint32(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)

	s, err = keyToReadable(uint64(4))
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
}
