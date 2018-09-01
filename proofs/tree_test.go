package proofs

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/xsleonard/go-merkle"
)

var testSalt = []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225}
var sha256Hash = sha256.New()

type UnsupportedType struct {
	supported bool
}

func TestValueToString(t *testing.T) {
	v, err := ValueToString(nil)
	assert.Equal(t, "", v)
	assert.Nil(t, err)

	v, err = ValueToString(int64(0))
	assert.Equal(t, "0", v, "int64(0) to string failed")
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

func TestConcatValues(t *testing.T) {
	val, err := ConcatValues("prop", strconv.FormatInt(int64(0), 10), testSalt)
	assert.Nil(t, err)
	v, _ := ValueToString(int64(0))
	expectedPayload := append([]byte("prop"), v...)
	expectedPayload = append(expectedPayload, testSalt...)
	assert.Equal(t, expectedPayload, val)
}

func TestLeafNode_HashNode(t *testing.T) {
	intLeaf := LeafNode{
		Property: "fieldName",
		Value:    strconv.FormatInt(int64(42), 10),
		Salt:     testSalt,
	}

	h := sha256.New()
	err := intLeaf.HashNode(h)
	assert.Nil(t, err)
	expectedHash := []byte{0x3f, 0xdc, 0x3e, 0xc3, 0x52, 0xc7, 0xa3, 0xc5, 0xe4, 0x6e, 0x2c, 0x4b, 0xa6, 0x16, 0x34, 0x6, 0x18, 0x25, 0x9a, 0x5a, 0x50, 0x9e, 0x94, 0x25, 0xf8, 0x9a, 0x45, 0x25, 0x89, 0x6b, 0x1b, 0xb8}
	assert.Equal(t, expectedHash, intLeaf.Hash)

	// Hashing again should fail because intLeaf.Hash is filled
	err = intLeaf.HashNode(h)
	assert.EqualError(t, err, "Hash already set")

	invalidSaltLeaf := LeafNode{
		Property: "fieldName",
		Value:    strconv.FormatInt(int64(42), 10),
		Salt:     []byte{},
	}
	err = invalidSaltLeaf.HashNode(h)
	assert.EqualError(t, err, "fieldName: Salt has incorrect length: 0 instead of 32")

}

func TestNormalizeDottedProperty(t *testing.T) {
	value := "valueA.valueB[0].valueC"
	expected := "ValueA.ValueB[0].ValueC"
	assert.Equal(t, expected, normalizeDottedProperty(value))

	value = "value_a.value_b.valueC[4].value"
	expected = "ValueA.ValueB.ValueC[4].Value"
	assert.Equal(t, expected, normalizeDottedProperty(value))
}

func TestGetDottedValueByProperty(t *testing.T) {
	doc := &documentspb.ExampleFilledNestedRepeatedDocument
	value, err := getDottedValueByProperty("valueD.valueB", doc)
	assert.Nil(t, err)
	assert.Equal(t, "ValueDB", value)

	value, err = getDottedValueByProperty("valueD.valueA.valueA", doc)
	assert.Nil(t, err)
	assert.Equal(t, "ValueDAA", value)

	value, err = getDottedValueByProperty("valueC[1].valueA", doc)
	assert.Nil(t, err)
	assert.Equal(t, "ValueCB", value)

	wrongDoc := "wrong!"
	value, err = getDottedValueByProperty("valueC[1]", wrongDoc)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "non-struct interface not supported")
}

func TestGetFieldOfStruct(t *testing.T) {
	doc := &documentspb.FilledExampleDocument
	value, err := getFieldOfStruct(doc, "ValueA")
	assert.Nil(t, err)
	assert.Equal(t, "Example", value.(string))

	value, err = getFieldOfStruct(doc, "WrongField")
	assert.NotNil(t, err)
	assert.EqualError(t, err, "No such field: WrongField in obj")

	wrongDoc := "wrong!"
	value, err = getFieldOfStruct(wrongDoc, "ValueA")
	assert.NotNil(t, err)
	assert.EqualError(t, err, "getFieldOfStruct invoked with a non-struct interface")
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
	leaves, err := FlattenMessage(&message, &messageSalts, DefaultSaltsLengthSuffix, sha256Hash)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(leaves))

	propOrder := []string{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []string{"ValueCamelCased", "value1", "value2", "valueA", "valueB", "value_bytes1", "value_not_hashed", "value_not_ignored"}, propOrder)

	v, _ := ValueToString("Foo")
	expectedPayload := append([]byte("valueA"), v...)
	expectedPayload = append(expectedPayload, messageSalts.ValueA[:]...)
	expectedHash := sha256.Sum256(expectedPayload)
	leaves[3].HashNode(sha256Hash)
	assert.Equal(t, expectedHash[:], leaves[3].Hash)
}

func TestFlattenMessage_AllFieldTypes(t *testing.T) {
	message := documentspb.NewAllFieldTypes()
	messageSalts := documentspb.AllFieldTypesSalts{}
	err := FillSalts(message, &messageSalts)
	assert.Nil(t, err)

	leaves, err := FlattenMessage(message, &messageSalts, DefaultSaltsLengthSuffix, sha256Hash)
	propOrder := []string{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []string{"string_value", "time_stamp_value"}, propOrder)
	assert.Nil(t, err)

}

func TestFlattenMessage_HashedField(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	message := &documentspb.ExampleDocument{
		ValueA:         "foobar",
		ValueNotHashed: foobarHash[:],
	}

	messageSalts := documentspb.SaltedExampleDocument{}
	err := FillSalts(message, &messageSalts)
	assert.Nil(t, err)

	leaves, err := FlattenMessage(message, &messageSalts, DefaultSaltsLengthSuffix, sha256Hash)
	propOrder := []string{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []string{"ValueCamelCased", "value1", "value2", "valueA", "valueB", "value_bytes1", "value_not_hashed", "value_not_ignored"}, propOrder)
	assert.Nil(t, err)
	assert.Equal(t, leaves[6].Hash, foobarHash[:])
	assert.Equal(t, leaves[6].Value, "")

	invalidMessage := &documentspb.InvalidHashedFieldDocument{
		Value: "foobar",
	}

	leaves, err = FlattenMessage(invalidMessage, &messageSalts, DefaultSaltsLengthSuffix, sha256Hash)
	assert.EqualError(t, err, "The option hashed_field is only supported for type `bytes`")
}

func TestFlattenMessageFromAutoFillSalts(t *testing.T) {
	exampleFNDoc := &documentspb.ExampleFilledNestedRepeatedDocument
	exampleFNSalts := &documentspb.SaltedNestedRepeatedDocument{}
	err := FillSalts(exampleFNDoc, exampleFNSalts)
	assert.Nil(t, err, "Fill salts should not fail")

	assert.Equal(t, len(exampleFNDoc.ValueC), len(exampleFNSalts.ValueC))
	assert.NotNil(t, exampleFNSalts.ValueC[0].ValueA)
	assert.NotNil(t, exampleFNSalts.ValueD.ValueA.ValueA)

	leaves, err := FlattenMessage(exampleFNDoc, exampleFNSalts, DefaultSaltsLengthSuffix, sha256Hash)
	assert.Nil(t, err)
	propOrder := []string{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []string{"valueA", "valueB", "valueC.length", "valueC[0].valueA", "valueC[1].valueA", "valueD.valueA.valueA", "valueD.valueB"}, propOrder)
}

func TestFlattenMessageFromAlreadyFilledSalts(t *testing.T) {
	exampleDoc := &documentspb.ExampleFilledNestedRepeatedDocument
	exampleSaltedDoc := &documentspb.ExampleSaltedNestedRepeatedDocument
	leaves, err := FlattenMessage(exampleDoc, exampleSaltedDoc, DefaultSaltsLengthSuffix, sha256Hash)
	assert.Nil(t, err)
	propOrder := []string{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []string{"valueA", "valueB", "valueC.length", "valueC[0].valueA", "valueC[1].valueA", "valueD.valueA.valueA", "valueD.valueB"}, propOrder)
}

func TestTree_Generate(t *testing.T) {
	protoMessage := documentspb.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}

	messageSalts := documentspb.SaltedExampleDocument{
		ValueA:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1:     []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueNotIgnored: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueCamelCased: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}

	leaves, err := FlattenMessage(&protoMessage, &messageSalts, DefaultSaltsLengthSuffix, sha256Hash)
	assert.Nil(t, err)
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DisableHashLeaves: true})
	hashes := [][]byte{}
	assert.Equal(t, len(leaves), 8)
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}

	tree.Generate(hashes, sha256Hash)
	h := tree.Root().Hash
	expectedHash := []byte{0x65, 0xe, 0x12, 0x55, 0xba, 0x91, 0x61, 0xc4, 0x77, 0x18, 0x4a, 0x26, 0xe8, 0xb6, 0x8, 0x7d, 0x50, 0x8e, 0x7f, 0xc6, 0xb2, 0xc9, 0x37, 0x4d, 0xb3, 0x24, 0xe2, 0xfe, 0xc2, 0xe0, 0xd3, 0xfe}
	assert.Equal(t, h, expectedHash, "Hash should match")
}

func TestSortedHashTree_Generate(t *testing.T) {
	protoMessage := documentspb.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}

	messageSalts := documentspb.SaltedExampleDocument{
		ValueA:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueB:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value1:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		Value2:          []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueBytes1:     []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueNotIgnored: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
		ValueCamelCased: []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225},
	}

	leaves, err := FlattenMessage(&protoMessage, &messageSalts, DefaultSaltsLengthSuffix, sha256Hash)
	assert.Nil(t, err)
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DisableHashLeaves: true, EnableHashSorting: true})
	hashes := [][]byte{}
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}
	tree.Generate(hashes, sha256Hash)
	h := tree.Root().Hash
	expectedHash := []byte{0xdb, 0x6e, 0x15, 0x5b, 0x83, 0x5f, 0xbc, 0x12, 0x46, 0xd4, 0x7b, 0x13, 0x36, 0xdc, 0x32, 0x10, 0x12, 0xc8, 0xa1, 0xc9, 0x46, 0x6a, 0x87, 0x9e, 0xc, 0xaf, 0x44, 0xc3, 0xf3, 0xdd, 0x4f, 0x31}
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

func TestDocumentTree_Generate_twice(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.EqualError(t, err, "tree already filled")
}

// TestTree_hash tests calculating hashes both with sha256 and md5
func TestTree_hash(t *testing.T) {
	// MD5
	hashFuncMd5 := md5.New()
	doctree := NewDocumentTree(TreeOptions{Hash: hashFuncMd5})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := []byte{0x97, 0x6d, 0xb8, 0x98, 0x81, 0x19, 0x3f, 0x7f, 0x79, 0xb3, 0x60, 0xfc, 0x77, 0x64, 0x31, 0xd9}
	assert.Equal(t, expectedRootHash, doctree.rootHash)

	// No hash func set
	doctreeNoHash := NewDocumentTree(TreeOptions{})
	err = doctreeNoHash.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "hash is not set")

	// SHA256
	doctreeSha256 := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err = doctreeSha256.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)
	err = doctreeSha256.Generate()
	expectedRootHash = []byte{0xcf, 0x1, 0x81, 0xa8, 0xdc, 0x9b, 0xa3, 0x16, 0x97, 0xe3, 0x39, 0x6b, 0xa8, 0xfd, 0x12, 0xaf, 0x50, 0x4b, 0x51, 0x60, 0x93, 0xa5, 0xa9, 0x44, 0xd7, 0x8a, 0x69, 0x60, 0xc9, 0xe0, 0x32, 0x5b}
	assert.Equal(t, expectedRootHash, doctreeSha256.rootHash)
}

func TestTree_AddLeaf_hashed(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeaf(LeafNode{Hash: foobarHash[:], Property: "Foobar1", Hashed: true})
	assert.Nil(t, err)
	err = doctree.AddLeaf(LeafNode{Hash: foobarHash[:], Property: "Foobar2", Hashed: true})
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := sha256.Sum256(append(foobarHash[:], foobarHash[:]...))
	assert.Equal(t, expectedRootHash[:], doctree.RootHash())

	err = doctree.AddLeaf(LeafNode{Hash: foobarHash[:], Property: "Foobar1", Hashed: true})
	assert.EqualError(t, err, "tree already filled")
}

func TestTree_AddLeaves_hashed(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeaves([]LeafNode{
		LeafNode{Hash: foobarHash[:], Property: "Foobar1", Hashed: true},
		LeafNode{Hash: foobarHash[:], Property: "Foobar2", Hashed: true},
	})
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := sha256.Sum256(append(foobarHash[:], foobarHash[:]...))
	assert.Equal(t, expectedRootHash[:], doctree.RootHash())

	err = doctree.AddLeaves([]LeafNode{LeafNode{Hash: foobarHash[:], Property: "Foobar1", Hashed: true}})
	assert.EqualError(t, err, "tree already filled")
}

func TestTree_AddLeavesFromDocument_twice(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	length := len(doctree.leaves)
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)
	assert.Equal(t, length*2, len(doctree.leaves))
	err = doctree.Generate()
	assert.Nil(t, err)

	assert.Equal(t, doctree.leaves[0].Property, doctree.leaves[length].Property)

	expectedRootHash := []byte{0xad, 0x30, 0x25, 0x40, 0xa8, 0x59, 0xb2, 0x3f, 0x31, 0x7d, 0x5f, 0x6c, 0x44, 0xcb, 0xae, 0xab, 0x39, 0xc6, 0x39, 0xd5, 0xe0, 0x7a, 0x4d, 0xfb, 0x5e, 0x91, 0xc6, 0x1, 0x9a, 0xcd, 0x79, 0x10}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	hashes, err := doctree.pickHashesFromMerkleTree(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

}

func TestTree_GenerateStandardProof(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := []byte{0xcf, 0x1, 0x81, 0xa8, 0xdc, 0x9b, 0xa3, 0x16, 0x97, 0xe3, 0x39, 0x6b, 0xa8, 0xfd, 0x12, 0xaf, 0x50, 0x4b, 0x51, 0x60, 0x93, 0xa5, 0xa9, 0x44, 0xd7, 0x8a, 0x69, 0x60, 0xc9, 0xe0, 0x32, 0x5b}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	hashes, err := doctree.pickHashesFromMerkleTree(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_GenerateNestedTreeCombinedStandardProof(t *testing.T) {
	doctreeA := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctreeA.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument, &documentspb.ExampleSaltedRepeatedDocument)
	assert.Nil(t, err)

	err = doctreeA.Generate()
	assert.Nil(t, err)

	doctreeB := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	docB := &documentspb.FilledExampleDocument
	docB.ValueNotHashed = doctreeA.rootHash
	err = doctreeB.AddLeavesFromDocument(docB, &documentspb.ExampleDocumentSalts)
	assert.Nil(t, err)

	err = doctreeB.Generate()
	assert.Nil(t, err)

	expectedRootHashA := []byte{0xe9, 0x7a, 0x71, 0x75, 0xeb, 0xbf, 0xd9, 0x7a, 0x60, 0x8d, 0x7a, 0x52, 0xf2, 0x7b, 0x4f, 0x84, 0x71, 0xdc, 0xc0, 0x8d, 0x65, 0x64, 0xc7, 0xab, 0x8b, 0xf1, 0x1a, 0x9d, 0x6c, 0xa9, 0x85, 0x55}
	assert.Equal(t, expectedRootHashA, doctreeA.RootHash())

	expectedRootHashB := []byte{0xdd, 0x14, 0x6d, 0x29, 0x2a, 0x36, 0xbd, 0x6b, 0xd3, 0x6b, 0x64, 0x13, 0xf3, 0xcc, 0x94, 0x76, 0xc9, 0xf, 0x14, 0xc8, 0x8d, 0xd, 0x8d, 0x8f, 0x28, 0xd1, 0xc5, 0xc3, 0xf, 0x89, 0x7f, 0xa}
	assert.Equal(t, expectedRootHashB, doctreeB.RootHash())

	fieldProofA, err := doctreeA.CreateProof("valueA")
	assert.Nil(t, err)

	fieldHash := doctreeA.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, fieldProofA.Hashes, doctreeA.rootHash, doctreeA.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

	fieldProofB, err := doctreeB.CreateProof("value_not_hashed")
	assert.Nil(t, err)

	valid, err = ValidateProofHashes(docB.ValueNotHashed, fieldProofB.Hashes, doctreeB.rootHash, doctreeB.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

	combinedProof := fieldProofA
	combinedProof.Hashes = append(combinedProof.Hashes, fieldProofB.Hashes...)

	fieldHash = doctreeA.merkleTree.Nodes[0].Hash
	valid, err = ValidateProofHashes(fieldHash, combinedProof.Hashes, doctreeB.rootHash, doctreeB.hash)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_GenerateNestedTreeCombinedSortedHashesProof(t *testing.T) {
	doctreeA := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	err := doctreeA.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument, &documentspb.ExampleSaltedRepeatedDocument)
	assert.Nil(t, err)

	err = doctreeA.Generate()
	assert.Nil(t, err)

	doctreeB := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	docB := &documentspb.FilledExampleDocument
	docB.ValueNotHashed = doctreeA.rootHash
	err = doctreeB.AddLeavesFromDocument(docB, &documentspb.ExampleDocumentSalts)
	assert.Nil(t, err)

	err = doctreeB.Generate()
	assert.Nil(t, err)

	expectedRootHashA := []byte{0xfa, 0x84, 0xf0, 0x2c, 0xed, 0xea, 0x3, 0x99, 0x80, 0xd6, 0x2f, 0xfb, 0x7, 0x19, 0xc6, 0xe2, 0x36, 0x71, 0x99, 0xb4, 0xe4, 0x56, 0xe9, 0xa4, 0xf4, 0x96, 0xde, 0xa, 0xef, 0xbc, 0xd1, 0xd}
	assert.Equal(t, expectedRootHashA, doctreeA.RootHash())

	expectedRootHashB := []byte{0x50, 0xe0, 0x2d, 0xd6, 0xc6, 0xd7, 0xf4, 0xbb, 0x26, 0xf8, 0x9d, 0x38, 0xb3, 0x51, 0xf3, 0x97, 0xff, 0x85, 0xf3, 0xee, 0x3e, 0xb9, 0x9e, 0x61, 0x60, 0x76, 0xbb, 0xd2, 0x6e, 0x7, 0x9e, 0x78}
	assert.Equal(t, expectedRootHashB, doctreeB.RootHash())

	fieldProofA, err := doctreeA.CreateProof("valueA")
	assert.Nil(t, err)

	fieldHash := doctreeA.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofSortedHashes(fieldHash, fieldProofA.SortedHashes, doctreeA.rootHash, doctreeA.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

	fieldProofB, err := doctreeB.CreateProof("value_not_hashed")
	assert.Nil(t, err)

	valid, err = ValidateProofSortedHashes(docB.ValueNotHashed, fieldProofB.SortedHashes, doctreeB.rootHash, doctreeB.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

	combinedProof := fieldProofA
	combinedProof.SortedHashes = append(combinedProof.SortedHashes, fieldProofB.SortedHashes...)

	fieldHash = doctreeA.merkleTree.Nodes[0].Hash
	valid, err = ValidateProofSortedHashes(fieldHash, combinedProof.SortedHashes, doctreeB.rootHash, doctreeB.hash)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_GenerateProofHashed(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	hashA := sha256.Sum256([]byte("A"))
	hashB := sha256.Sum256([]byte("B"))
	hashC := sha256.Sum256([]byte("C"))
	hashD := sha256.Sum256([]byte("D"))

	doctree.AddLeaves([]LeafNode{
		LeafNode{Property: "A", Hash: hashA[:], Hashed: true},
		LeafNode{Property: "B", Hash: hashB[:], Hashed: true},
		LeafNode{Property: "C", Hash: hashC[:], Hashed: true},
		LeafNode{Property: "D", Hash: hashD[:], Hashed: true},
	})

	err := doctree.Generate()
	assert.Nil(t, err)

	n1 := sha256.Sum256(append(hashA[:], hashB[:]...))
	n2 := sha256.Sum256(append(hashC[:], hashD[:]...))
	root := sha256.Sum256(append(n1[:], n2[:]...))
	expectedRootHash := root[:]

	assert.Equal(t, expectedRootHash, doctree.RootHash())

	hashes, err := doctree.pickHashesFromMerkleTree(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

	fieldProof, err := doctree.CreateProof("A")
	assert.Nil(t, err)
	assert.Equal(t, fieldProof.Hash, doctree.leaves[0].Hash)
	valid, err = ValidateProofHashes(hashA[:], fieldProof.Hashes, doctree.rootHash, doctree.hash)
	assert.True(t, valid)
	assert.Nil(t, err)
	valid, err = doctree.ValidateProof(&fieldProof)
	assert.True(t, valid)
	assert.Nil(t, err)
}

func TestTree_GenerateSortedProof(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample, &documentspb.SaltedLongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := []byte{0x68, 0x36, 0x1f, 0x62, 0x5f, 0x8b, 0x5, 0x75, 0xc, 0x5e, 0x32, 0x85, 0x64, 0xcb, 0x45, 0xd0, 0x17, 0x66, 0xc0, 0x58, 0x3e, 0x9c, 0x19, 0xda, 0x53, 0x52, 0x81, 0x52, 0x44, 0x74, 0x79, 0xb7}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	hashes, err := doctree.pickHashesFromMerkleTreeAsList(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofSortedHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

}

func TestTree_GenerateWithRepeatedFields(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument, &documentspb.ExampleSaltedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	expectedRootHash := []byte{0xfa, 0x84, 0xf0, 0x2c, 0xed, 0xea, 0x3, 0x99, 0x80, 0xd6, 0x2f, 0xfb, 0x7, 0x19, 0xc6, 0xe2, 0x36, 0x71, 0x99, 0xb4, 0xe4, 0x56, 0xe9, 0xa4, 0xf4, 0x96, 0xde, 0xa, 0xef, 0xbc, 0xd1, 0xd}
	assert.Equal(t, expectedRootHash, doctree.RootHash())
	assert.Equal(t, []string{"valueA", "valueB", "valueC.length", "valueC[0]", "valueC[1]"}, doctree.PropertyOrder())

	hashes, err := doctree.pickHashesFromMerkleTreeAsList(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofSortedHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_GenerateWithNestedAndRepeatedFields(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument, &documentspb.ExampleSaltedNestedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	expectedRootHash := []byte{0x9a, 0x83, 0x33, 0xe7, 0x72, 0x54, 0x1b, 0x67, 0x5c, 0x3, 0x0, 0x9a, 0x1d, 0xa0, 0xa5, 0x15, 0xac, 0xeb, 0x0, 0x96, 0x6, 0x9c, 0xfb, 0x15, 0x90, 0x52, 0x6e, 0xa8, 0x74, 0x8, 0x7, 0x49}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	assert.Equal(t, []string{"valueA", "valueB", "valueC.length", "valueC[0].valueA", "valueC[1].valueA", "valueD.valueA.valueA", "valueD.valueB"}, doctree.PropertyOrder())

	hashes, err := doctree.pickHashesFromMerkleTreeAsList(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofSortedHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
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

func TestCreateProof_standard(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.FilledExampleDocument, &documentspb.ExampleDocumentSalts)
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueA")
	assert.EqualError(t, err, "Can't create proof before generating merkle root")

	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err = doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, "valueA", proof.Property)
	assert.Equal(t, documentspb.FilledExampleDocument.ValueA, proof.Value)
	assert.Equal(t, documentspb.ExampleDocumentSalts.ValueA, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x4f, 0x30, 0x6a, 0xa9, 0xf7, 0x81, 0xec, 0x85, 0x40, 0xaf, 0x3b, 0x5a, 0xfa, 0x3e, 0x88, 0xa2, 0xbe, 0x81, 0xed, 0x2b, 0xbe, 0x57, 0x8f, 0xb1, 0xd9, 0xc5, 0x99, 0xf1, 0xb5, 0x34, 0x90, 0xa}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueA")
	falseProof.Value = "Invalid"
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateProof_sorted(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.FilledExampleDocument, &documentspb.ExampleDocumentSalts)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err := doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, "valueA", proof.Property)
	assert.Equal(t, documentspb.FilledExampleDocument.ValueA, proof.Value)
	assert.Equal(t, documentspb.ExampleDocumentSalts.ValueA, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x50, 0xe0, 0x2d, 0xd6, 0xc6, 0xd7, 0xf4, 0xbb, 0x26, 0xf8, 0x9d, 0x38, 0xb3, 0x51, 0xf3, 0x97, 0xff, 0x85, 0xf3, 0xee, 0x3e, 0xb9, 0x9e, 0x61, 0x60, 0x76, 0xbb, 0xd2, 0x6e, 0x7, 0x9e, 0x78}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofSortedHashes(fieldHash, proof.SortedHashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueA")
	falseProof.Value = "Invalid"
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateRepeatedSortedProof(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument, &documentspb.ExampleSaltedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err := doctree.CreateProof("valueC[1]")
	assert.Nil(t, err)
	assert.Equal(t, "valueC[1]", proof.Property)
	assert.Equal(t, documentspb.ExampleFilledRepeatedDocument.ValueC[1], proof.Value)
	assert.Equal(t, documentspb.ExampleSaltedRepeatedDocument.ValueC[1], proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0xfa, 0x84, 0xf0, 0x2c, 0xed, 0xea, 0x3, 0x99, 0x80, 0xd6, 0x2f, 0xfb, 0x7, 0x19, 0xc6, 0xe2, 0x36, 0x71, 0x99, 0xb4, 0xe4, 0x56, 0xe9, 0xa4, 0xf4, 0x96, 0xde, 0xa, 0xef, 0xbc, 0xd1, 0xd}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofSortedHashes(fieldHash, proof.SortedHashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueC[1]")
	falseProof.Value = "Invalid"
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateRepeatedSortedProofAutoSalts(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	docSalts := &documentspb.SaltedNestedRepeatedDocument{}
	err := FillSalts(&documentspb.ExampleFilledNestedRepeatedDocument, docSalts)
	assert.Nil(t, err)

	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument, docSalts)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err := doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, "valueA", proof.Property)
	assert.Equal(t, documentspb.ExampleFilledRepeatedDocument.ValueA, proof.Value)
	assert.Equal(t, docSalts.ValueA, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	valid, err := ValidateProofSortedHashes(fieldHash, proof.SortedHashes, doctree.rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueA")
	falseProof.Value = "Invalid"
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateProofFromRepeatedField(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	docSalts := &documentspb.SaltedNestedRepeatedDocument{}
	err := FillSalts(&documentspb.ExampleFilledNestedRepeatedDocument, docSalts)
	assert.Nil(t, err)

	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument, docSalts)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueC[1].valueA")
	assert.Nil(t, err)
	assert.Equal(t, "valueC[1].valueA", proof.Property)
	assert.Equal(t, documentspb.ExampleFilledNestedRepeatedDocument.ValueC[1].ValueA, proof.Value)
	assert.Equal(t, docSalts.ValueC[1].ValueA, proof.Salt)
}

func TestCreateProofFromNestedField(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash})
	docSalts := &documentspb.SaltedNestedRepeatedDocument{}
	err := FillSalts(&documentspb.ExampleFilledNestedRepeatedDocument, docSalts)
	assert.Nil(t, err)

	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument, docSalts)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueD.valueA.valueA")
	assert.Nil(t, err)
	assert.Equal(t, "valueD.valueA.valueA", proof.Property)
	assert.Equal(t, documentspb.ExampleFilledNestedRepeatedDocument.ValueD.ValueA.ValueA, proof.Value)
	assert.Equal(t, docSalts.ValueD.ValueA.ValueA, proof.Salt)
}

func Example_complete() {
	// ExampleDocument is a protobuf message
	document := documentspb.ExampleDocument{
		Value1:      1,
		ValueA:      "Foo",
		ValueB:      "Bar",
		ValueBytes1: []byte("foobar"),
	}

	// The FillSalts method is a helper function that fills all fields with 32
	// random bytes. SaltedExampleDocument is a protobuf message that has the
	// same structure as ExampleDocument but has all `bytes` field types.
	salts := documentspb.SaltedExampleDocument{}
	FillSalts(&document, &salts)

	doctree := NewDocumentTree(TreeOptions{Hash: sha256.New()})
	doctree.AddLeavesFromDocument(&document, &salts)
	doctree.Generate()
	fmt.Printf("Generated tree: %s\n", doctree.String())

	proof, _ := doctree.CreateProof("ValueA")
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	valid, _ := doctree.ValidateProof(&proof)

	fmt.Printf("Proof validated: %v\n", valid)
}
