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

	_, _, err = ExtractFieldTags("a,42,c,packed")
	assert.EqualError(t, err, "not enough elements in protobuf tag list")

	name, num, err = ExtractFieldTags("a,42,c,packed,name=d")
	assert.NoError(t, err)
	assert.Equal(t, "d", name)
	assert.Equal(t, FieldNum(42), num)
}

func TestPropertyName_NoParent(t *testing.T) {

	fieldProp := Empty.FieldProp("field", 43)
	assert.Equal(t, "field", fieldProp.ReadableName())
	assert.Equal(t, []byte{0, 0, 0, 43}, fieldProp.CompactName())

	sliceElemProp := Empty.SliceElemProp(5)
	assert.Equal(t, "5", sliceElemProp.ReadableName())
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 5}, sliceElemProp.CompactName())

	mapElemProp, err := Empty.MapElemProp(fmt.Errorf("not a valid key type"), 32)
	assert.Error(t, err)

	mapElemProp, err = Empty.MapElemProp("keykeykeykeykeykeykeykeykeykeykey", 32)
	assert.Error(t, err)

	mapElemProp, err = Empty.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, "key", mapElemProp.ReadableName())
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 107, 101, 121}, mapElemProp.CompactName())

	testLengthSuffix := "_precise"
	lengthProp := Empty.LengthProp(testLengthSuffix)
	assert.Equal(t, testLengthSuffix, lengthProp.ReadableName())
	assert.Equal(t, []byte(nil), lengthProp.CompactName())
}

func TestPropertyName_Parent(t *testing.T) {
	baseProp := NewProperty("base", 42)
	assert.Equal(t, "base", baseProp.ReadableName())
	assert.Equal(t, []byte{42}, baseProp.CompactName())

	fieldProp := baseProp.FieldProp("field", 43)
	assert.Equal(t, "base.field", fieldProp.ReadableName())
	assert.Equal(t, []byte{42, 0, 0, 0, 43}, fieldProp.CompactName())

	sliceElemProp := baseProp.SliceElemProp(5)
	assert.Equal(t, "base[5]", sliceElemProp.ReadableName())
	assert.Equal(t, []byte{42, 0, 0, 0, 0, 0, 0, 0, 5}, sliceElemProp.CompactName())

	mapElemProp, err := baseProp.MapElemProp(fmt.Errorf("not a valid key type"), 32)
	assert.Error(t, err)

	mapElemProp, err = baseProp.MapElemProp("keykeykeykeykeykeykeykeykeykeykey", 32)
	assert.Error(t, err)

	mapElemProp, err = baseProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, "base[key]", mapElemProp.ReadableName())
	assert.Equal(t, []byte{42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 107, 101, 121}, mapElemProp.CompactName())

	testLengthSuffix := "length"
	lengthProp := baseProp.LengthProp(testLengthSuffix)
	assert.Equal(t, "base." + testLengthSuffix, lengthProp.ReadableName())
	assert.Equal(t, []byte{42}, lengthProp.CompactName())
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
		[]byte{1, 255, 2, 254},
		AsBytes(CompactName(1, 255, 2, 254)),
	)
}

func TestKeyNames(t *testing.T) {
	_, _, err := keyNames("key", 0)
	assert.Error(t, err)

	s, bs, err := keyNames("key", 8)
	assert.NoError(t, err)
	assert.Equal(t, "key", s)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 107, 101, 121}, bs)

	s, bs, err = keyNames(42, 0)
	assert.NoError(t, err)
	assert.Equal(t, "42", s)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 42}, bs)

	_, _, err = keyNames([]byte{0x2f, 0xa2, 0x93}, 0)
	assert.Error(t, err)

	s, bs, err = keyNames([]byte{0x2f, 0xa2, 0x93}, 8)
	assert.NoError(t, err)
	assert.Equal(t, "0x2fa293", s)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0x2f, 0xa2, 0x93}, bs)

	_, _, err = keyNames(`foo[bar].foo\bar`, 0)
	assert.Error(t, err)

	s, bs, err = keyNames(`foo[bar].foo\bar`, 20)
	assert.NoError(t, err)
	assert.Equal(t, `foo\[bar\]\.foo\\bar`, s)
	assert.Equal(t, []byte(`foo\[bar\]\.foo\\bar`), bs)

	s, bs, err = keyNames(true, 0)
	assert.NoError(t, err)
	assert.Equal(t, "true", s)
	assert.Equal(t, []byte{1}, bs)

	s, bs, err = keyNames(int(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 4}, bs)

	s, bs, err = keyNames(int8(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{4}, bs)

	s, bs, err = keyNames(int16(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{0, 4}, bs)

	s, bs, err = keyNames(int32(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{0, 0, 0, 4}, bs)

	s, bs, err = keyNames(int64(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 4}, bs)

	s, bs, err = keyNames(uint(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 4}, bs)

	s, bs, err = keyNames(uint8(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{4}, bs)

	s, bs, err = keyNames(uint16(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0, 4}, bs)
	assert.Equal(t, "4", s)

	s, bs, err = keyNames(uint32(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{0, 0, 0, 4}, bs)

	s, bs, err = keyNames(uint64(4), 0)
	assert.NoError(t, err)
	assert.Equal(t, "4", s)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 4}, bs)
}
