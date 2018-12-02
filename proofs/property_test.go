package proofs

import (
    "testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractFieldTags(t * testing.T) {

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
