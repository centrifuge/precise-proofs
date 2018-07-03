package proofs

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/xsleonard/go-merkle"
	"testing"
	"time"
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
	ts.UnmarshalJSON([]byte(fmt.Sprintf("\"%s\"", documentspb.ExampleTimeString)))
	pt, _ := ptypes.TimestampProto(ts)
	v, err = ValueToString(pt)
	assert.Equal(t, documentspb.ExampleTimeString, v)
	assert.Nil(t, err)

	// Test empty pointer (zero value)
	var emptyTimestamp *timestamp.Timestamp
	emptyTimestamp = nil
	v, err = ValueToString(emptyTimestamp)
	assert.Equal(t, "", v)
	assert.Nil(t, err)
}

func TestConcatNode(t *testing.T) {
	salt := []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225}
	intLeaf := LeafNode{
		Property: "fieldName",
		Value:    int64(42),
		Salt:     salt,
	}

	// Test the payload format:
	payload, err := ConcatNode(&intLeaf)
	assert.Nil(t, err)

	v, _ := ValueToString(intLeaf.Value)
	expectedPayload := append([]byte(intLeaf.Property), v...)
	expectedPayload = append(expectedPayload, intLeaf.Salt[:]...)

	assert.Equal(t, expectedPayload, payload, "Concatenated payload doesn't match")

	hash := sha256.Sum256(payload)
	expectedHash := []byte{0x3f, 0xdc, 0x3e, 0xc3, 0x52, 0xc7, 0xa3, 0xc5, 0xe4, 0x6e, 0x2c, 0x4b, 0xa6, 0x16, 0x34, 0x6, 0x18, 0x25, 0x9a, 0x5a, 0x50, 0x9e, 0x94, 0x25, 0xf8, 0x9a, 0x45, 0x25, 0x89, 0x6b, 0x1b, 0xb8}
	assert.Equal(t, expectedHash, hash[:], "Hash for integer leaf doesn't match")

	invalidSaltLeaf := LeafNode{
		Property: "fieldName",
		Value:    int64(42),
		Salt:     []byte{},
	}
	_, err = ConcatNode(&invalidSaltLeaf)
	assert.Error(t, errors.New("Salt has incorrect length: 0 instead of 32"), err)

}

func TestFlattenMessage(t *testing.T) {
	message := documentspb.ExampleDocument{
		ValueA: "Foo",
	}

	messageSalts := documentspb.SaltedExampleDocument{
		ValueA:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1:     []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueCamelCased: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueNotIgnored: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}
	flattened, propOrder, err := FlattenMessage(&message, &messageSalts)
	assert.Nil(t, err)
	assert.Equal(t, 7, len(flattened))
	assert.Equal(t, []string{"ValueCamelCased", "value1", "value2", "valueA", "valueB", "value_bytes1", "value_not_ignored"}, propOrder)

	v, _ := ValueToString("Foo")
	expectedPayload := append([]byte("valueA"), v...)
	expectedPayload = append(expectedPayload, messageSalts.ValueA[:]...)
	assert.Equal(t, expectedPayload, flattened[3])
}

func TestFlattenMessage_AllFieldTypes(t *testing.T) {
	message := documentspb.NewAllFieldTypes()
	messageSalts := documentspb.AllFieldTypesSalts{}
	FillSalts(&messageSalts)

	_, fieldOrder, err := FlattenMessage(message, &messageSalts)
	assert.Equal(t, []string{"string_value", "time_stamp_value"}, fieldOrder)
	assert.Nil(t, err)

}

func TestFillSalts(t *testing.T) {
	// Fill a properly formatted document
	exampleSalts := &documentspb.SaltedExampleDocument{}
	err := FillSalts(exampleSalts)
	assert.Nil(t, err, "Fill salts should not fail")

	badExample := &documentspb.ExampleDocument{}
	err = FillSalts(badExample)
	assert.NotNil(t, err, "Fill salts should error because of string")
}

func TestTree_Generate(t *testing.T) {
	protoMessage := documentspb.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}
	messageSalts := documentspb.SaltedExampleDocument{
		ValueA:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:      []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}

	flattened, _, _ := FlattenMessage(&protoMessage, &messageSalts)
	tree := merkle.NewTree()
	sha256Hash := sha256.New()
	tree.Generate(flattened, sha256Hash)
	h := tree.Root().Hash
	expectedHash := []byte{0xfa, 0x4a, 0x1a, 0x35, 0x43, 0x4f, 0xff, 0x8c, 0xeb, 0x59, 0x8a, 0xfe, 0xe8, 0x31, 0x5b, 0x8b, 0x9e, 0x5c, 0xd1, 0xed, 0x87, 0x75, 0xb9, 0x79, 0x9c, 0xfd, 0x7, 0xd7, 0xfc, 0xd5, 0x9e, 0x34}
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

func BenchmarkCalculateProofNodeList(b *testing.B) {
	for n := 0; n < b.N; n++ {
		CalculateProofNodeList(50, 100)
	}
}

// TestTree_SetHashFunc tests calculating hashes both with sha256 and md5
func TestTree_SetHashFunc(t *testing.T) {
	doctree := NewDocumentTree()
	hashFuncMd5 := md5.New()
	doctree.SetHashFunc(hashFuncMd5)
	err := doctree.FillTree(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)

	expectedRootHash := []byte{0x97, 0x6d, 0xb8, 0x98, 0x81, 0x19, 0x3f, 0x7f, 0x79, 0xb3, 0x60, 0xfc, 0x77, 0x64, 0x31, 0xd9}
	assert.Equal(t, expectedRootHash, doctree.rootHash)

	doctreeSha256 := NewDocumentTree()
	hashFuncSha256 := sha256.New()
	doctreeSha256.SetHashFunc(hashFuncSha256)
	err = doctreeSha256.FillTree(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)

	expectedRootHash = []byte{0xcf, 0x1, 0x81, 0xa8, 0xdc, 0x9b, 0xa3, 0x16, 0x97, 0xe3, 0x39, 0x6b, 0xa8, 0xfd, 0x12, 0xaf, 0x50, 0x4b, 0x51, 0x60, 0x93, 0xa5, 0xa9, 0x44, 0xd7, 0x8a, 0x69, 0x60, 0xc9, 0xe0, 0x32, 0x5b}
	assert.Equal(t, expectedRootHash, doctreeSha256.rootHash)
}

func TestTree_GenerateProof(t *testing.T) {
	doctree := NewDocumentTree()
	hashFunc := sha256.New()
	doctree.SetHashFunc(hashFunc)
	err := doctree.FillTree(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)

	expectedRootHash := []byte{0xcf, 0x1, 0x81, 0xa8, 0xdc, 0x9b, 0xa3, 0x16, 0x97, 0xe3, 0x39, 0x6b, 0xa8, 0xfd, 0x12, 0xaf, 0x50, 0x4b, 0x51, 0x60, 0x93, 0xa5, 0xa9, 0x44, 0xd7, 0x8a, 0x69, 0x60, 0xc9, 0xe0, 0x32, 0x5b}
	assert.Equal(t, expectedRootHash, doctree.rootHash)

	hashes, err := doctree.pickHashesFromMerkleTree(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

}

func TestGetStringValueByProperty(t *testing.T) {
	value, err := getStringValueByProperty("valueA", &documentspb.FilledExampleDocument)
	assert.Nil(t, err)
	assert.Equal(t, documentspb.FilledExampleDocument.ValueA, value)
	doc := &documentspb.ExampleDocument{ValueCamelCased: []byte{2}, ValueBytes1: []byte{2}}
	value, err = getStringValueByProperty("ValueCamelCased", doc)
	assert.Nil(t, err)
	assert.Equal(t, "Ag==", value)
	value, err = getStringValueByProperty("value_bytes1", doc)
	assert.Nil(t, err)
	assert.Equal(t, "Ag==", value)
}

func TestCreateProof(t *testing.T) {
	doctree := NewDocumentTree()
	hashFunc := sha256.New()
	doctree.SetHashFunc(hashFunc)
	err := doctree.FillTree(&documentspb.FilledExampleDocument, &documentspb.ExampleDocumentSalts)
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, "valueA", proof.Property)
	assert.Equal(t, documentspb.FilledExampleDocument.ValueA, proof.Value)
	assert.Equal(t, documentspb.ExampleDocumentSalts.ValueA, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, hashFunc)
	rootHash := []byte{0xff, 0x75, 0x97, 0xc1, 0x1e, 0xb3, 0xa0, 0x62, 0x44, 0x22, 0xe5, 0x4c, 0x4c, 0x1b, 0x83, 0xa3, 0x2a, 0x5e, 0xaa, 0x71, 0xdb, 0x65, 0x93, 0x98, 0x67, 0x51, 0x16, 0x10, 0x1, 0x7f, 0x1c, 0xea}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash, doctree.hash)
	assert.True(t, valid)
}
