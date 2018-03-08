package tree

import (
	"bytes"
	"fmt"
	"github.com/centrifuge/precise-proofs/example"
	"github.com/stretchr/testify/assert"
	merkle "github.com/xsleonard/go-merkle"
	"golang.org/x/crypto/blake2b"
	"testing"
	"encoding/base64"
)

func TestValueToString(t *testing.T) {
	v, _ := ValueToString(int64(42))
	assert.Equal(t, "42", v, "int64(42) to string failed")

	v, _ = ValueToString("Hello World.")
	assert.Equal(t, "Hello World.", v, "string(\"Hello World\".) to string failed")

	v, _ = ValueToString([]byte("42"))
	expected := base64.StdEncoding.EncodeToString([]byte("42"))
	assert.Equal(t, expected, v, "[]byte(\"42\") to string failed")

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
	expectedPayload := append([]byte(intLeaf.Property), []byte(NodeValueSeparator)...)
	expectedPayload = append(expectedPayload, v...)
	expectedPayload = append(expectedPayload, []byte(NodeValueSeparator)...)
	expectedPayload = append(expectedPayload, intLeaf.Salt[:]...)

	if !bytes.Equal(payload, expectedPayload) {
		t.Fatal("Concatenated payload doesn't match")
	}

	hash := blake2b.Sum256(payload)
	expectedHash := []byte{0xf0, 0xf1, 0x5f, 0xa5, 0x9b, 0x9b, 0x62, 0xe4, 0x58, 0x85, 0x9a, 0x64, 0x8b, 0x21, 0x4, 0xbf, 0x6f, 0x91, 0xc4, 0x4e, 0x3e, 0x93, 0x30, 0xe3, 0x68, 0x32, 0x77, 0x6f, 0xda, 0x39, 0x17, 0xb3}

	assert.Equal(t, expectedHash, hash[:], "Hash for integer leaf doesn't match")
}

func TestFlatten(t *testing.T) {
	message := example.ExampleDocument{
		ValueA: "Foo",
	}

	messageSalts := example.SaltedExampleDocument{
		ValueA:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}
	flattened, _, err := FlattenMessage(&message, &messageSalts)
	assert.Equal(t, nil, err)
	assert.Equal(t, 5, len(flattened))

	v, _ := ValueToString("Foo")
	expected_payload := append([]byte("ValueA"), []byte(NodeValueSeparator)...)
	expected_payload = append(expected_payload, v...)
	expected_payload = append(expected_payload, []byte(NodeValueSeparator)...)
	expected_payload = append(expected_payload, messageSalts.ValueA[:]...)
	assert.Equal(t, expected_payload, flattened[2])
}

func TestFillSalts(t *testing.T) {
	// Fill a properly formatted Document
	exampleSalts := &example.SaltedExampleDocument{}
	err := FillSalts(exampleSalts)
	assert.Nil(t, err, "Fill Salts should not fail")

	badExample := &example.ExampleDocument{}
	err = FillSalts(badExample)
	assert.NotEqual(t, err, nil, "Fill Salts should error because of string")
}

func TestTree_Generate(t *testing.T) {
	protoMessage := example.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}
	messageSalts := example.SaltedExampleDocument{
		ValueA:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}

	flattened, _, _ := FlattenMessage(&protoMessage, &messageSalts)
	tree := merkle.NewTree()
	blakeHash, _ := blake2b.New256([]byte{})
	tree.Generate(flattened, blakeHash)
	h := tree.Root().Hash
	expectedHash := []byte{0x57, 0x9b, 0x2f, 0x38, 0xfb, 0x6f, 0x54, 0xc0, 0xbd, 0x11, 0xc9, 0x5c, 0x2f, 0xfc, 0x72, 0x0, 0xba, 0x5c, 0x50, 0x87, 0x2e, 0x77, 0x45, 0x83, 0xdf, 0xbe, 0x75, 0x3, 0xda, 0x66, 0xd6, 0x6a}
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
//			&HashNode{true, 5},
//			&HashNode{true, 5},
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
				fmt.Sprintf("CalculateProofNodeList(%d, %d), node #: %d, %s, %d", input[0], input[1], j, results[i][j].Left, results[i][j].Leaf))

			assert.Equal(t,
				results[i][j].Leaf,
				n.Leaf,
				fmt.Sprintf("CalculateProofNodeList(%d, %d) hash %d was leaf %d expected %d", input[0], input[1], j, n.Leaf, results[i][j].Leaf))
		}
	}

}

func TestTree_GenerateProof(t *testing.T) {
	doctree := NewDocumentTree()
	doctree.AddDocument(&example.LongDocumentExample, &example.SaltedLongDocumentExample)

	expectedRootHash := []byte{0x2a, 0xdb, 0x4, 0x7f, 0x3f, 0xa5, 0xba, 0xe6, 0x18, 0xb, 0x3d, 0xd6, 0xad, 0x78, 0xd, 0xc9, 0xd, 0xac, 0xe2, 0x54, 0xe6, 0x6b, 0x3c, 0x39, 0xf2, 0xf6, 0xe, 0x30, 0x74, 0x57, 0x91, 0x3c}

	assert.Equal(t, expectedRootHash, doctree.RootHash)

	hashes, err := doctree.pickHashesFromMerkleTree( 0)
	assert.Nil(t, err)
	fieldHash := doctree.MerkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.RootHash)
	assert.Nil(t, err)
	assert.True(t, valid)

}

func TestGetStringValueByProperty(t *testing.T) {
	value, _ := getStringValueByProperty("ValueA", &example.FilledExampleDocument)
	assert.Equal(t, example.FilledExampleDocument.ValueA, value)
}

func Test_CreateProof(t *testing.T) {
	doctree := NewDocumentTree()
	doctree.AddDocument(&example.FilledExampleDocument, &example.ExampleDocumentSalts)

	proof, err := doctree.CreateProof("ValueA")
	assert.Nil(t, err)
	assert.Equal(t, "ValueA", proof.Property)
	assert.Equal(t, example.FilledExampleDocument.ValueA, proof.Value)
	assert.Equal(t, example.ExampleDocumentSalts.ValueA, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof)
	rootHash := []byte{0xb2, 0xd3, 0xa2, 0xe5, 0xe5, 0xab, 0x4a, 0x3a, 0x26, 0xa9, 0xdc, 0x50, 0x3d, 0x2, 0xc9, 0x5, 0x8e, 0x33, 0xf8, 0x34, 0xde, 0x8a, 0x5e, 0x83, 0x2c, 0x1f, 0xe9, 0x36, 0x13, 0xd7, 0x16, 0x3c}
	assert.Equal(t, rootHash, doctree.RootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash)
	assert.True(t, valid)

}
