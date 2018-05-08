package proofs

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/xsleonard/go-merkle"
	"golang.org/x/crypto/blake2b"
	"testing"
	"encoding/base64"
	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/golang/protobuf/ptypes"
	"time"
	"github.com/golang/protobuf/ptypes/timestamp"
	"crypto/sha256"
)

type UnsupportedType struct {
	supported bool
}

func TestValueToString(t *testing.T) {
	v, err := ValueToString(nil)
	assert.Equal(t, "", v)
	assert.Nil(t, err)

	v, err = ValueToString(int64(42))
	assert.Equal(t, "42", v, "int64(42) to string failed")
	assert.Nil(t, err)

	v, err = ValueToString("Hello World.")
	assert.Equal(t, "Hello World.", v, "string(\"Hello World\".) to string failed")
	assert.Nil(t, err)

	v, err = ValueToString([]byte("42"))
	expected := base64.StdEncoding.EncodeToString([]byte("42"))
	assert.Equal(t, expected, v, "[]byte(\"42\") to string failed")
	assert.Nil(t, err)

	v, err = ValueToString(UnsupportedType{false})
	assert.Equal(t, "", v)
	assert.Error(t, err)

	// Timestamp
	ts := time.Now()
	ts.UnmarshalJSON([]byte(fmt.Sprintf("\"%s\"", documents.ExampleTimeString)))
	pt, _ := ptypes.TimestampProto(ts)
	v, err = ValueToString(pt)
	assert.Equal(t, documents.ExampleTimeString, v)
	assert.Nil(t, err)

	// Test empty pointer (zero value)
	var emptyTimestamp *timestamp.Timestamp;
	emptyTimestamp = nil
	v, err = ValueToString(emptyTimestamp)
	assert.Equal(t, "", v)
	assert.Nil(t, err)
}

func TestLeaf(t *testing.T) {
	salt := []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225}
	intLeaf := LeafNode{
		Property: "fieldName",
		Value:    int64(42),
		Salt:     salt,
	}

	// Test the payload format:
	payload, _ := ConcatNode(&intLeaf)
	v, _ := ValueToString(intLeaf.Value)
	expectedPayload := append([]byte(intLeaf.Property), v...)
	expectedPayload = append(expectedPayload, intLeaf.Salt[:]...)

	assert.Equal(t, expectedPayload, payload, "Concatenated payload doesn't match")

	hash := blake2b.Sum256(payload)
	expectedHash := []byte{0xd2, 0x97, 0x1c, 0x9f, 0x70, 0x8b, 0x1f, 0xc1, 0x61, 0x29, 0xac, 0xb8, 0x56, 0xa3, 0x26, 0xe4, 0x49, 0xff, 0xa0, 0x2a, 0x26, 0xae, 0xba, 0x21, 0x62, 0x2d, 0x20, 0x9b, 0xb7, 0xfb, 0x26, 0xd3}

	assert.Equal(t, expectedHash, hash[:], "Hash for integer leaf doesn't match")
}

func TestFlatten(t *testing.T) {
	message := documents.ExampleDocument{
		ValueA: "Foo",
	}

	messageSalts := documents.SaltedExampleDocument{
		ValueA:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}
	flattened, propOrder, err := FlattenMessage(&message, &messageSalts)
	assert.Equal(t, nil, err)
	assert.Equal(t, 5, len(flattened))
	assert.Equal(t, []string{"Value1", "Value2", "ValueA", "ValueB", "ValueBytes1"}, propOrder)

	v, _ := ValueToString("Foo")
	expectedPayload := append([]byte("ValueA"), v...)
	expectedPayload = append(expectedPayload, messageSalts.ValueA[:]...)
	assert.Equal(t, expectedPayload, flattened[2])
}

func TestFlatten_AllFieldTypes(t *testing.T) {
	message := documents.NewAllFieldTypes()
	messageSalts := documents.AllFieldTypesSalts{}
	FillSalts(&messageSalts)

	_, fieldOrder, err := FlattenMessage(message, &messageSalts)
	assert.Equal(t, []string{"StringValue", "TimestampValue"}, fieldOrder)
	assert.Nil(t, err)

}

func TestFillSalts(t *testing.T) {
	// Fill a properly formatted document
	exampleSalts := &documents.SaltedExampleDocument{}
	err := FillSalts(exampleSalts)
	assert.Nil(t, err, "Fill salts should not fail")

	badExample := &documents.ExampleDocument{}
	err = FillSalts(badExample)
	assert.NotEqual(t, err, nil, "Fill salts should error because of string")
}

func TestTree_Generate(t *testing.T) {
	protoMessage := documents.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}
	messageSalts := documents.SaltedExampleDocument{
		ValueA:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}

	flattened, _, _ := FlattenMessage(&protoMessage, &messageSalts)
	tree := merkle.NewTree()
	blakeHash, _ := blake2b.New256(nil)
	tree.Generate(flattened, blakeHash)
	h := tree.Root().Hash
	expectedHash := []byte{0xdd, 0x2d, 0xef, 0x0, 0xbb, 0xd3, 0xdd, 0x84, 0x1c, 0x1, 0x16, 0x83, 0xaf, 0x17, 0x53, 0xb5, 0x5, 0xbb, 0x66, 0x16, 0x39, 0xf0, 0x64, 0x1a, 0x17, 0xe1, 0x94, 0x9f, 0x4d, 0xbd, 0xfb, 0x88}
	assert.Equal(t, expectedHash, h, "Hash should match")
}

func TestCalculateProofNodeList(t *testing.T) {
	inputs := [][]uint64{
		{0, 15},
		{1, 15},
		{2, 15},
		{3, 15},
		{4, 15},
		{5, 15},
		{6, 15},
		{7, 15},
		{12, 15},
		{13, 15},
		{14, 15}, // Lone child edge case
		{15, 16}, // Last node
		{0, 2},   // Two leaves, one level
		{0, 4},
		{2, 3},
		{2, 5},
		{6, 7},
	}

	results := [][]*HashNode{
		// 0, 15
		{
			&HashNode{false, 1},
			&HashNode{false, 16},
			&HashNode{false, 24},
			&HashNode{false, 28},
		},
		// 1, 15
		{
			&HashNode{true, 0},
			&HashNode{false, 16},
			&HashNode{false, 24},
			&HashNode{false, 28},
		},
		// 2, 15
		{
			&HashNode{false, 3},
			&HashNode{true, 15},
			&HashNode{false, 24},
			&HashNode{false, 28},
		},
		// 3, 15
		{
			&HashNode{true, 2},
			&HashNode{true, 15},
			&HashNode{false, 24},
			&HashNode{false, 28},
		},
		// 4, 15
		{
			&HashNode{false, 5},
			&HashNode{false, 18},
			&HashNode{true, 23},
			&HashNode{false, 28},
		},
		// 5, 15
		{
			&HashNode{true, 4},
			&HashNode{false, 18},
			&HashNode{true, 23},
			&HashNode{false, 28},
		},
		// 6, 15
		{
			&HashNode{false, 7},
			&HashNode{true, 17},
			&HashNode{true, 23},
			&HashNode{false, 28},
		},
		// 7, 15
		{
			&HashNode{true, 6},
			&HashNode{true, 17},
			&HashNode{true, 23},
			&HashNode{false, 28},
		},
		// 12, 15
		{
			&HashNode{false, 13},
			&HashNode{false, 22},
			&HashNode{true, 25},
			&HashNode{true, 27},
		},
		// 13, 15
		{
			&HashNode{true, 12},
			&HashNode{false, 22},
			&HashNode{true, 25},
			&HashNode{true, 27},
		},
		// 14, 15
		{
			&HashNode{true, 21},
			&HashNode{true, 25},
			&HashNode{true, 27},
		},
		// 15, 16
		{
			&HashNode{true, 14},
			&HashNode{true, 22},
			&HashNode{true, 26},
			&HashNode{true, 28},
		},
		// 0, 2
		{
			&HashNode{false, 1},
		},

		// 4 Leaf Tree:
		//       6
		//   4       5
		// 0   1   2   3
		//
		// 0, 4
		{
			&HashNode{false, 1},
			&HashNode{false, 5},
		},
		// 3 Leaf Tree:
		//     5
		//   3    4 (2)
		// 0   1   2
		//
		// 2, 3
		{
			&HashNode{true, 3},
		},
		// 5 Leaf Tree:
		//             8
		//        8        9 (4)
		//   5       6     7 (4)
		// 0   1   2   3   4
		//
		// 2, 5
		{
			&HashNode{false, 3},
			&HashNode{true, 5},
			&HashNode{false, 9},
		},
		// 7 Leaf Tree:
		//               14
		//        11              12
		//   7       8       9     10 (6)
		// 0   1   2   3   4   5   6
		//
		// 6, 7
		{
			&HashNode{true, 9},
			&HashNode{true, 11},
		},
	}

	for i, input := range inputs {
		r, _ := CalculateProofNodeList(input[0], input[1])
		assert.Equal(t,
			len(results[i]),
			len(r),
			fmt.Sprintf("CalculateProofNodeList(%d, %d), Result Length Mismatch", input[0], input[1]))

		for j, n := range r {
			assert.Equal(t,
				results[i][j].Left,
				n.Left,
				fmt.Sprintf("CalculateProofNodeList(%d, %d), node #: %d, %t, %d", input[0], input[1], j, results[i][j].Left, results[i][j].Leaf))

			assert.Equal(t,
				results[i][j].Leaf,
				n.Leaf,
				fmt.Sprintf("CalculateProofNodeList(%d, %d) hash %d was leaf %d expected %d", input[0], input[1], j, n.Leaf, results[i][j].Leaf))
		}
	}

}

// TestTree_SetHashFunc tests calculating hashes both with sha256 & blake2b
func TestTree_SetHashFunc(t *testing.T) {
	doctree := NewDocumentTree()
	hashFunc, err := blake2b.New256(nil)
	assert.Nil(t, err)
	doctree.SetHashFunc(hashFunc)
	doctree.FillTree(&documents.LongDocumentExample, &documents.SaltedLongDocumentExample)

	expectedRootHash := []byte{0x87, 0xec, 0xe2, 0xbc, 0xe3, 0x55, 0x69, 0xf0, 0x43, 0x94, 0xca, 0x2f, 0xdc, 0xd1, 0xd8, 0x4d, 0xb0, 0x5c, 0x11, 0xc4, 0x4b, 0x54, 0x62, 0x70, 0x94, 0xc, 0xe5, 0x3e, 0x19, 0xe9, 0x44, 0x38}
	assert.Equal(t, expectedRootHash, doctree.rootHash)

	doctreeSha256 := NewDocumentTree()
	hashFuncSha256 := sha256.New()
	assert.Nil(t, err)
	doctreeSha256.SetHashFunc(hashFuncSha256)
	doctreeSha256.FillTree(&documents.LongDocumentExample, &documents.SaltedLongDocumentExample)

	expectedRootHash = []byte{0x61, 0xa7, 0x8f, 0x4a, 0xbb, 0xce, 0xa1, 0x2c, 0x17, 0x80, 0xa4, 0xd2, 0xa1, 0x91, 0xf8, 0x39, 0x64, 0xe8, 0xd7, 0xe7, 0xf7, 0xbe, 0xc5, 0x75, 0xe3, 0x0, 0xa9, 0xcf, 0xda, 0xb5, 0xa8, 0x28}
	assert.Equal(t, expectedRootHash, doctreeSha256.rootHash)
}

func TestTree_GenerateProof(t *testing.T) {
	doctree := NewDocumentTree()
	hashFunc, err := blake2b.New256(nil)
	assert.Nil(t, err)
	doctree.SetHashFunc(hashFunc)
	doctree.FillTree(&documents.LongDocumentExample, &documents.SaltedLongDocumentExample)

	expectedRootHash := []byte{0x87, 0xec, 0xe2, 0xbc, 0xe3, 0x55, 0x69, 0xf0, 0x43, 0x94, 0xca, 0x2f, 0xdc, 0xd1, 0xd8, 0x4d, 0xb0, 0x5c, 0x11, 0xc4, 0x4b, 0x54, 0x62, 0x70, 0x94, 0xc, 0xe5, 0x3e, 0x19, 0xe9, 0x44, 0x38}

	assert.Equal(t, expectedRootHash, doctree.rootHash)

	hashes, err := doctree.pickHashesFromMerkleTree(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

}

func TestGetStringValueByProperty(t *testing.T) {
	value, _ := getStringValueByProperty("ValueA", &documents.FilledExampleDocument)
	assert.Equal(t, documents.FilledExampleDocument.ValueA, value)
}

func Test_CreateProof(t *testing.T) {
	doctree := NewDocumentTree()
	hashFunc, _ := blake2b.New256(nil)
	doctree.SetHashFunc(hashFunc)
	doctree.FillTree(&documents.FilledExampleDocument, &documents.ExampleDocumentSalts)

	proof, err := doctree.CreateProof("ValueA")
	assert.Nil(t, err)
	assert.Equal(t, "ValueA", proof.Property)
	assert.Equal(t, documents.FilledExampleDocument.ValueA, proof.Value)
	assert.Equal(t, documents.ExampleDocumentSalts.ValueA, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, hashFunc)
	rootHash := []byte{0x54, 0xb1, 0xe6, 0xb2, 0x42, 0x2a, 0x74, 0xc6, 0x57, 0xa8, 0x7f, 0x2a, 0x80, 0xac, 0xb, 0x27, 0x3f, 0xd9, 0x76, 0x5d, 0xe2, 0x59, 0xc1, 0xdf, 0x8a, 0x4d, 0xd4, 0x3d, 0xa0, 0xfe, 0x62, 0x5c}

	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash, doctree.hash)
	assert.True(t, valid)

}
