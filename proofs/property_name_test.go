package proofs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFieldNamePath_AsBytes(t *testing.T) {
	assert.Equal(t, []byte{65, 66, 67, 68, 69}, FieldNamePath("ABCDE").AsBytes())
}

func TestFieldNumPath_AsBytes(t *testing.T) {
	assert.Equal(t,
		[]byte{
			0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 0, 0, 0, 0, 0, 255,
			0, 0, 0, 0, 0, 0, 1, 0,
			0, 0, 0, 0, 0, 1, 0, 0,
			0, 0, 0, 0, 0, 0, 255, 255,
		},
		FieldNumPath([]FieldNum{1, 255, 256, 256 * 256, 256*256 - 1}).AsBytes(),
	)
}

func TestLiteralPropName_AsBytes(t *testing.T) {
	assert.Equal(t,
		[]byte{1, 2, 3, 4, 5},
		LiteralPropName([]byte{1, 2, 3, 4, 5}).AsBytes(),
	)
}
