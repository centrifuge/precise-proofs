package proofs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
