package proofs

import (
	"crypto/md5"
	"crypto/sha256"
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
	"github.com/pkg/errors"
)

var testSalt = []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225}

func NewSaltForTest(compact []byte) (salt []byte, err error) {
	return testSalt, nil
}

func NewSaltForErrorTest(compact []byte) (salt []byte, err error) {
	return nil, errors.New("Cannot get salt")
}

var sha256Hash = sha256.New()

type UnsupportedType struct {
	supported bool
}

func TestValueToBytesArray(t *testing.T) {
	f := &messageFlattener{}
	v, err := f.valueToBytesArray(nil)
	assert.Equal(t, []byte{}, v)
	assert.Nil(t, err)

	v, err = f.valueToBytesArray(int64(42))
	assert.Equal(t, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2a}, v)
	assert.Nil(t, err)

	v, err = f.valueToBytesArray("Hello World.")
	assert.Equal(t, []byte("Hello World."), v)
	assert.Nil(t, err)

	b := []byte("42")
	v, err = f.valueToBytesArray(b)
	assert.Equal(t, b, v)
	assert.Nil(t, err)

	v, err = f.valueToBytesArray(UnsupportedType{false})
	assert.Equal(t, []byte{}, v)
	assert.Error(t, err)

	// Timestamp
	ts := time.Now()
	expected, err := toBytesArray(ts.Unix())
	assert.NoError(t, err)
	pt, _ := ptypes.TimestampProto(ts)
	v, err = f.valueToBytesArray(pt)
	assert.Equal(t, expected, v)
	assert.Nil(t, err)

	// Test empty pointer (zero value)
	var emptyTimestamp *timestamp.Timestamp
	emptyTimestamp = nil
	v, err = f.valueToBytesArray(emptyTimestamp)
	assert.Equal(t, []byte{}, v)
	assert.Nil(t, err)
}

func TestConcatValues(t *testing.T) {
	b := []byte{1}
	val, err := ConcatValues(ReadableName("prop"), b, testSalt)
	assert.Nil(t, err)
	f := &messageFlattener{}
	v, _ := f.valueToBytesArray(b)
	expectedPayload := append([]byte("prop"), v...)
	expectedPayload = append(expectedPayload, testSalt...)
	assert.Equal(t, expectedPayload, val)
}

func TestLeafNode_HashNode(t *testing.T) {
	prop := NewProperty("fieldName", 42)
	intLeaf := LeafNode{
		Property: prop,
		Value:    []byte(strconv.FormatInt(int64(42), 10)),
		Salt:     testSalt,
	}

	h := sha256.New()
	err := intLeaf.HashNode(h, false)
	assert.Nil(t, err)
	expectedHash := []byte{0x3f, 0xdc, 0x3e, 0xc3, 0x52, 0xc7, 0xa3, 0xc5, 0xe4, 0x6e, 0x2c, 0x4b, 0xa6, 0x16, 0x34, 0x6, 0x18, 0x25, 0x9a, 0x5a, 0x50, 0x9e, 0x94, 0x25, 0xf8, 0x9a, 0x45, 0x25, 0x89, 0x6b, 0x1b, 0xb8}
	assert.Equal(t, expectedHash, intLeaf.Hash)

	h.Reset()
	intLeaf.Hash = nil
	err = intLeaf.HashNode(h, true)
	assert.Nil(t, err)
	expectedHash = []byte{0x29, 0xf9, 0x4f, 0xe4, 0xc7, 0x3f, 0xaf, 0x40, 0x9c, 0x13, 0x81, 0x6f, 0xd1, 0xd8, 0x8b, 0x8a, 0xd9, 0x83, 0x80, 0xc, 0xe6, 0x5e, 0xeb, 0xd3, 0x3a, 0xa1, 0xe3, 0x77, 0x51, 0x42, 0x66, 0x55}
	assert.Equal(t, expectedHash, intLeaf.Hash)

	invalidSaltLeaf := LeafNode{
		Property: prop,
		Value:    []byte(strconv.FormatInt(int64(42), 10)),
		Salt:     []byte{},
	}
	err = invalidSaltLeaf.HashNode(h, false)
	assert.EqualError(t, err, "fieldName: Salt has incorrect length: 0 instead of 32")
	err = invalidSaltLeaf.HashNode(h, true)
	assert.EqualError(t, err, "[42]: Salt has incorrect length: 0 instead of 32")

}

func TestTree_Generate(t *testing.T) {
	protoMessage := documentspb.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}

	leaves, err := FlattenMessage(&protoMessage, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty)
	assert.NoError(t, err)
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DisableHashLeaves: true})
	var hashes [][]byte
	assert.Equal(t, 9, len(leaves))
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}

	tree.Generate(hashes, sha256Hash)
	h := tree.Root().Hash
	expectedHash := []byte{0x62, 0xc7, 0xd8, 0x7b, 0xda, 0xb7, 0xde, 0xbd, 0x9c, 0x6b, 0x95, 0x6f, 0xe9, 0x18, 0x98, 0x9, 0x57, 0x70, 0x15, 0x75, 0x7c, 0x73, 0x4c, 0x75, 0x37, 0x62, 0x17, 0xf7, 0x32, 0x24, 0x66, 0xa}
	assert.Equal(t, expectedHash, h, "Hash should match")
}

func TestSortedHashTree_Generate(t *testing.T) {
	protoMessage := documentspb.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}

	leaves, err := FlattenMessage(&protoMessage, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty)
	assert.NoError(t, err)
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DisableHashLeaves: true, EnableHashSorting: true})
	var hashes [][]byte
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}
	tree.Generate(hashes, sha256Hash)
	h := tree.Root().Hash
	expectedHash := []byte{0x84, 0xe4, 0xbc, 0x6d, 0xf7, 0xf0, 0xfe, 0xf5, 0xe8, 0x24, 0xe0, 0x7b, 0x9b, 0x27, 0x47, 0xf2, 0x7, 0x98, 0x65, 0x6e, 0xf3, 0xc9, 0x63, 0x6c, 0xf2, 0xb6, 0x7e, 0xcc, 0xb6, 0x92, 0x91, 0xdf}
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

func TestDocumentTree_ToStringNilEncoder(t *testing.T) {
	doctree := &DocumentTree{}
	assert.Equal(t, "DocumentTree with Hash [] and [0] leaves", doctree.String())
}

func TestDocumentTree_Generate_twice(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.EqualError(t, err, "tree already filled")
}

// Test DocumentTree sets rootHash correctly and validated the generated Proof
func TestDocumentTree_WithRootHash(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
	assert.NoError(t, err)

	err = doctree.Generate()
	assert.NoError(t, err)

	expectedRootHash := []byte{0x16, 0xce, 0xc4, 0xa8, 0xb5, 0xf, 0xe4, 0xf4, 0x1a, 0x47, 0x4, 0xfa, 0xe0, 0x3f, 0x45, 0x7f, 0xad, 0x8e, 0x6b, 0x8e, 0x1c, 0xff, 0x2c, 0x7b, 0x47, 0x4f, 0xbb, 0x36, 0xc0, 0x74, 0xef, 0x70}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	proof, err := doctree.CreateProof("valueA")
	assert.NoError(t, err)

	valid, err := doctree.ValidateProof(&proof)
	assert.Nil(t, err)
	assert.True(t, valid)

	// Generate doctree with RootHash set and validate the above generated Proof
	doctreeWithRootHash := NewDocumentTreeWithRootHash(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest}, expectedRootHash)
	assert.Equal(t, expectedRootHash, doctreeWithRootHash.rootHash)

	valid, err = doctreeWithRootHash.ValidateProof(&proof)
	assert.Nil(t, err)
	assert.True(t, valid)
}

// TestTree_hash tests calculating hashes both with sha256 and md5
func TestTree_hash(t *testing.T) {
	// MD5
	hashFuncMd5 := md5.New()
	doctree := NewDocumentTree(TreeOptions{Hash: hashFuncMd5, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := []byte{0xea, 0xa2, 0x2c, 0xc4, 0x1b, 0x91, 0x96, 0x23, 0x66, 0xc6, 0xa0, 0x8f, 0xaa, 0x49, 0xc0, 0xe8}
	assert.Equal(t, expectedRootHash, doctree.rootHash)

	// No hash func set
	doctreeNoHash := NewDocumentTree(TreeOptions{Salts: NewSaltForTest})
	err = doctreeNoHash.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "hash is not set")

	// SHA256
	doctreeSha256 := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err = doctreeSha256.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctreeSha256.Generate()
	expectedRootHash = []byte{0xe1, 0xee, 0x59, 0x40, 0xb8, 0x2c, 0x2b, 0xb4, 0x44, 0xa0, 0x4e, 0xe2, 0x3, 0x87, 0x27, 0xe8, 0x3a, 0xaa, 0xfd, 0xb0, 0x77, 0x70, 0x56, 0x5a, 0x5c, 0x40, 0xb3, 0x57, 0x14, 0x3d, 0xf0, 0xb5}
	assert.Equal(t, expectedRootHash, doctreeSha256.rootHash)
}

func TestTree_AddLeaf_hashed(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeaf(
		LeafNode{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar1"},
			Hashed:   true,
		},
	)
	assert.Nil(t, err)
	err = doctree.AddLeaf(
		LeafNode{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar2"},
			Hashed:   true,
		},
	)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := sha256.Sum256(append(foobarHash[:], foobarHash[:]...))
	assert.Equal(t, expectedRootHash[:], doctree.RootHash())

	err = doctree.AddLeaf(
		LeafNode{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar1"},
			Hashed:   true,
		},
	)
	assert.EqualError(t, err, "tree already filled")
}

func TestTree_AddLeaves_hashed(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeaves([]LeafNode{
		{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar1"},
			Hashed:   true,
		},
		{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar2"},
			Hashed:   true,
		},
	})
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := sha256.Sum256(append(foobarHash[:], foobarHash[:]...))
	assert.Equal(t, expectedRootHash[:], doctree.RootHash())

	err = doctree.AddLeaves([]LeafNode{
		{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar1"},
			Hashed:   true,
		},
	})
	assert.EqualError(t, err, "tree already filled")
}

func TestTree_AddLeavesFromDocument_twice(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	length := len(doctree.leaves)
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	assert.Equal(t, length*2, len(doctree.leaves))
	err = doctree.Generate()
	assert.Nil(t, err)

	assert.Equal(t, doctree.leaves[0].Property, doctree.leaves[length].Property)

	expectedRootHash := []byte{0xb6, 0x41, 0xd9, 0xab, 0x37, 0x4a, 0x33, 0x15, 0x71, 0x42, 0x91, 0x58, 0x8e, 0xe3, 0x38, 0xf3, 0x75, 0x8c, 0xd2, 0xbf, 0xdd, 0xd4, 0x47, 0x1e, 0xed, 0x1, 0x52, 0xd6, 0xb7, 0x71, 0x5e, 0x59}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	hashes, err := doctree.pickHashesFromMerkleTree(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

}

func TestTree_GenerateStandardProof(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := []byte{0xe1, 0xee, 0x59, 0x40, 0xb8, 0x2c, 0x2b, 0xb4, 0x44, 0xa0, 0x4e, 0xe2, 0x3, 0x87, 0x27, 0xe8, 0x3a, 0xaa, 0xfd, 0xb0, 0x77, 0x70, 0x56, 0x5a, 0x5c, 0x40, 0xb3, 0x57, 0x14, 0x3d, 0xf0, 0xb5}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	hashes, err := doctree.pickHashesFromMerkleTree(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_GenerateNestedTreeCombinedStandardProof(t *testing.T) {
	doctreeA := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctreeA.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
	assert.Nil(t, err)

	err = doctreeA.Generate()
	assert.NoError(t, err)

	doctreeB := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	docB := &documentspb.ExampleDocument{
		ValueA:         "Example",
		ValueNotHashed: doctreeA.rootHash,
	}
	err = doctreeB.AddLeavesFromDocument(docB)
	assert.NoError(t, err)

	err = doctreeB.Generate()
	assert.NoError(t, err)

	expectedRootHashA := []byte{0x16, 0xce, 0xc4, 0xa8, 0xb5, 0xf, 0xe4, 0xf4, 0x1a, 0x47, 0x4, 0xfa, 0xe0, 0x3f, 0x45, 0x7f, 0xad, 0x8e, 0x6b, 0x8e, 0x1c, 0xff, 0x2c, 0x7b, 0x47, 0x4f, 0xbb, 0x36, 0xc0, 0x74, 0xef, 0x70}
	assert.Equal(t, expectedRootHashA, doctreeA.RootHash())

	expectedRootHashB := []byte{0xcd, 0xef, 0x2a, 0x55, 0x26, 0x5b, 0x4, 0xa1, 0xc2, 0x72, 0x84, 0x5, 0x9, 0x34, 0xd3, 0xeb, 0x89, 0x31, 0x4c, 0xaa, 0xd7, 0xef, 0x7c, 0x28, 0x79, 0xb9, 0xd5, 0x9e, 0xdd, 0xf8, 0xaf, 0xd8}
	assert.Equal(t, expectedRootHashB, doctreeB.RootHash())

	fieldProofA, err := doctreeA.CreateProof("valueA")
	assert.NoError(t, err)

	fieldHash := doctreeA.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofHashes(fieldHash, fieldProofA.Hashes, doctreeA.rootHash, doctreeA.hash)
	assert.NoError(t, err)
	assert.True(t, valid)

	fieldProofB, err := doctreeB.CreateProof("value_not_hashed")
	assert.NoError(t, err)

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
	doctreeA := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctreeA.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
	assert.Nil(t, err)

	err = doctreeA.Generate()
	assert.Nil(t, err)

	doctreeB := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	docB := &documentspb.ExampleDocument{
		ValueA:         "Example",
		ValueNotHashed: doctreeA.rootHash,
	}
	err = doctreeB.AddLeavesFromDocument(docB)
	assert.Nil(t, err)

	err = doctreeB.Generate()
	assert.Nil(t, err)

	expectedRootHashA := []byte{0x16, 0xce, 0xc4, 0xa8, 0xb5, 0xf, 0xe4, 0xf4, 0x1a, 0x47, 0x4, 0xfa, 0xe0, 0x3f, 0x45, 0x7f, 0xad, 0x8e, 0x6b, 0x8e, 0x1c, 0xff, 0x2c, 0x7b, 0x47, 0x4f, 0xbb, 0x36, 0xc0, 0x74, 0xef, 0x70}
	assert.Equal(t, expectedRootHashA, doctreeA.RootHash())

	expectedRootHashB := []byte{0xd2, 0xe8, 0xd5, 0x57, 0x8c, 0x5e, 0xa5, 0xfc, 0x70, 0xf6, 0xb7, 0xf3, 0x87, 0xf7, 0x54, 0x55, 0xc7, 0x76, 0x35, 0xd6, 0xcc, 0xf1, 0xcd, 0x4f, 0x7, 0xb7, 0x65, 0xcb, 0x74, 0xff, 0xb, 0x9d}
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
		{
			Property: Property{Text: "A"},
			Hash:     hashA[:],
			Hashed:   true,
		},
		{
			Property: Property{Text: "B"},
			Hash:     hashB[:],
			Hashed:   true,
		},
		{
			Property: Property{Text: "C"},
			Hash:     hashC[:],
			Hashed:   true,
		},
		{
			Property: Property{Text: "D"},
			Hash:     hashD[:],
			Hashed:   true,
		},
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
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := []byte{0xcf, 0x1d, 0x69, 0xd7, 0xe0, 0x81, 0x40, 0xc5, 0x2e, 0xc0, 0xf4, 0xbf, 0x40, 0x9c, 0x2d, 0xbc, 0x28, 0x71, 0x13, 0x89, 0x86, 0xa5, 0x92, 0xea, 0x31, 0x49, 0x8, 0x15, 0x47, 0x93, 0xc3, 0xad}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	hashes, err := doctree.pickHashesFromMerkleTreeAsList(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofSortedHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)

}

func TestTree_GenerateWithRepeatedFields(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	expectedRootHash := []byte{0x16, 0xce, 0xc4, 0xa8, 0xb5, 0xf, 0xe4, 0xf4, 0x1a, 0x47, 0x4, 0xfa, 0xe0, 0x3f, 0x45, 0x7f, 0xad, 0x8e, 0x6b, 0x8e, 0x1c, 0xff, 0x2c, 0x7b, 0x47, 0x4f, 0xbb, 0x36, 0xc0, 0x74, 0xef, 0x70}
	assert.Equal(t, expectedRootHash, doctree.RootHash())
	propOrder := doctree.PropertyOrder()
	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("valueC", 3).LengthProp(DefaultReadablePropertyLengthSuffix),
		Empty.FieldProp("valueC", 3).SliceElemProp(0),
		Empty.FieldProp("valueC", 3).SliceElemProp(1),
	}, propOrder)

	hashes, err := doctree.pickHashesFromMerkleTreeAsList(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofSortedHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_GenerateWithNestedAndRepeatedFields(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	expectedRootHash := []byte{0x0, 0x9, 0xa1, 0xef, 0x58, 0x71, 0xef, 0x9f, 0xf6, 0x81, 0x6, 0xb0, 0x8d, 0x2f, 0x36, 0x5a, 0x76, 0xa7, 0x6b, 0x53, 0xb1, 0x80, 0xc4, 0x5, 0x4b, 0x29, 0x6, 0x40, 0xa8, 0x20, 0x63, 0xba}
	assert.Equal(t, expectedRootHash, doctree.RootHash())

	propOrder := doctree.PropertyOrder()

	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("valueC", 3).LengthProp(DefaultReadablePropertyLengthSuffix),
		Empty.FieldProp("valueC", 3).SliceElemProp(0).FieldProp("valueA", 1),
		Empty.FieldProp("valueC", 3).SliceElemProp(1).FieldProp("valueA", 1),
		Empty.FieldProp("valueD", 4).FieldProp("valueA", 1).FieldProp("valueA", 1),
		Empty.FieldProp("valueD", 4).FieldProp("valueB", 2),
	}, propOrder)

	hashes, err := doctree.pickHashesFromMerkleTreeAsList(0)
	assert.Nil(t, err)
	fieldHash := doctree.merkleTree.Nodes[0].Hash
	valid, err := ValidateProofSortedHashes(fieldHash, hashes, doctree.rootHash, doctree.hash)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestCreateProof_standard(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	doc := documentspb.FilledExampleDocument
	doc.ValueNotHashed = sha256Hash.Sum([]byte("some hash"))
	doc.ValueBytes1 = []byte("ValueBytes1")
	err := doctree.AddLeavesFromDocument(&doc)
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueA")
	assert.EqualError(t, err, "Can't create proof before generating merkle root")

	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err = doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.FilledExampleDocument.ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)

	proofB, err := doctree.CreateProof("value_bytes1")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("value_bytes1"), proofB.Property)
	assert.Equal(t, doc.ValueBytes1, proofB.Value)
	assert.Equal(t, testSalt, proofB.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x2a, 0xf5, 0x36, 0xea, 0x7f, 0xc6, 0xde, 0x5f, 0xf2, 0x37, 0xa8, 0x96, 0x5, 0xb0, 0x57, 0x81, 0xe7, 0x98, 0xf, 0x3e, 0x7b, 0x33, 0xab, 0x95, 0x54, 0xbe, 0xdd, 0xb, 0xa9, 0x69, 0x17, 0x5f}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	valid, err = doctree.ValidateProof(&proofB)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueA")
	falseProof.Value = []byte{}
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateProof_compact(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	doc := documentspb.FilledExampleDocument
	doc.ValueNotHashed = sha256Hash.Sum([]byte("some hash"))
	doc.ValueBytes1 = []byte("ValueBytes1")
	err := doctree.AddLeavesFromDocument(&doc)
	assert.Nil(t, err)

	proof, err := doctree.CreateProofWithCompactProp(doctree.GetCompactPropByPropertyName("valueA"))
	assert.EqualError(t, err, "Can't create proof before generating merkle root")

	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProofWithCompactProp([]byte{1, 1, 1, 1})
	assert.EqualError(t, err, "No such field: 01010101 in obj")

	proof, err = doctree.CreateProofWithCompactProp(doctree.GetCompactPropByPropertyName("valueA"))
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.FilledExampleDocument.ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)

	proofB, err := doctree.CreateProofWithCompactProp(doctree.GetCompactPropByPropertyName("value_bytes1"))
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("value_bytes1"), proofB.Property)
	assert.Equal(t, doc.ValueBytes1, proofB.Value)
	assert.Equal(t, testSalt, proofB.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x2a, 0xf5, 0x36, 0xea, 0x7f, 0xc6, 0xde, 0x5f, 0xf2, 0x37, 0xa8, 0x96, 0x5, 0xb0, 0x57, 0x81, 0xe7, 0x98, 0xf, 0x3e, 0x7b, 0x33, 0xab, 0x95, 0x54, 0xbe, 0xdd, 0xb, 0xa9, 0x69, 0x17, 0x5f}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	valid, err = doctree.ValidateProof(&proofB)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProofWithCompactProp(doctree.GetCompactPropByPropertyName("valueA"))
	falseProof.Value = []byte{}
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")

	// nested
	docNested := documentspb.ExampleFilledNestedRepeatedDocument
	doctree = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err = doctree.AddLeavesFromDocument(&docNested)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	s := doctree.GetCompactPropByPropertyName("valueD.valueB")
	proof, err = doctree.CreateProofWithCompactProp(s)
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueD.valueB"), proof.Property)
	assert.Equal(t, []byte(documentspb.ExampleFilledNestedRepeatedDocument.ValueD.ValueB), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)
}

func TestCreateProof_standard_compactProperties(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, CompactProperties: true, Salts: NewSaltForTest})
	doc := documentspb.FilledExampleDocument
	doc.ValueBytes1 = []byte("ValueBytes1")
	err := doctree.AddLeavesFromDocument(&doc)
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueA")
	assert.EqualError(t, err, "Can't create proof before generating merkle root")

	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err = doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, CompactName(0, 0, 0, 1), proof.Property)
	assert.Equal(t, []byte(documentspb.FilledExampleDocument.ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)

	proofB, err := doctree.CreateProofWithCompactProp(doctree.GetCompactPropByPropertyName("value_bytes1"))
	assert.Nil(t, err)
	assert.Equal(t, CompactName(0, 0, 0, 5), proofB.Property)
	assert.Equal(t, doc.ValueBytes1, proofB.Value)
	assert.Equal(t, testSalt, proofB.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x3c, 0x35, 0xe1, 0x7a, 0xfe, 0x6d, 0x1f, 0xea, 0x52, 0x10, 0xa3, 0x95, 0xe6, 0xb6, 0x26, 0xee, 0x44, 0x36, 0x10, 0x7a, 0xa5, 0x6f, 0xa3, 0xf9, 0x7c, 0x92, 0x4e, 0xa3, 0xa5, 0xf0, 0x5d, 0xec}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	valid, err = doctree.ValidateProof(&proofB)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueA")
	falseProof.Value = []byte{}
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateOneofProof(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleOneofSampleDocument)
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("valueC")
	assert.EqualError(t, err, "No such field: valueC in obj")

	proof, err := doctree.CreateProof("valueB")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueB"), proof.Property)
	ev, err := toBytesArray(documentspb.ExampleOneofSampleDocument.OneofBlock.(*documentspb.OneofSample_ValueB).ValueB)
	assert.NoError(t, err)
	assert.Equal(t, ev, proof.Value)
	assert.Equal(t, testSalt, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x8, 0x98, 0x8d, 0x75, 0x33, 0xac, 0xc, 0xad, 0x96, 0x2c, 0x9, 0x38, 0x37, 0x2e, 0x44, 0x32, 0x3c, 0x1c, 0xa1, 0xe5, 0xf3, 0x35, 0xdb, 0x21, 0x9f, 0x97, 0x8e, 0x6b, 0x17, 0x4e, 0xa5, 0xa2}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofHashes(fieldHash, proof.Hashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	doctree = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err = doctree.AddLeavesFromDocument(&documentspb.OneofSample{
		OneofBlock: &documentspb.OneofSample_ValueC{"bor"},
	})
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("valueB")
	assert.EqualError(t, err, "No such field: valueB in obj")
	_, err = doctree.CreateProof("valueC")
	assert.Nil(t, err)

	doctree = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err = doctree.AddLeavesFromDocument(&documentspb.OneofSample{
		OneofBlock: &documentspb.OneofSample_ValueD{&documentspb.SimpleItem{ValueA: "testA"}},
	})
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("valueC")
	assert.EqualError(t, err, "No such field: valueC in obj")
	_, err = doctree.CreateProof("valueD.valueA")
	assert.Nil(t, err)

	doctree = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err = doctree.AddLeavesFromDocument(&documentspb.OneofSample{})
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("valueB")
	assert.EqualError(t, err, "No such field: valueB in obj")
	_, err = doctree.CreateProof("valueD.valueA")
	assert.EqualError(t, err, "No such field: valueD.valueA in obj")
	_, err = doctree.CreateProof("valueC")
	assert.EqualError(t, err, "No such field: valueC in obj")

}

func TestCreateProof_sorted(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.FilledExampleDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err := doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.FilledExampleDocument.ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x64, 0x2, 0x7a, 0xcb, 0x10, 0x9f, 0x4d, 0x88, 0x37, 0x54, 0x94, 0xee, 0xeb, 0x70, 0xf8, 0xe7, 0xf0, 0x20, 0x66, 0x8d, 0x4d, 0xc7, 0xf6, 0x7, 0xc5, 0x8b, 0x6f, 0x2f, 0x1f, 0x38, 0xf3, 0x21}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofSortedHashes(fieldHash, proof.SortedHashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueA")
	falseProof.Value = []byte{}
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateRepeatedSortedProof(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err := doctree.CreateProof("valueC[1]")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueC[1]"), proof.Property)
	assert.Equal(t, []byte(documentspb.ExampleFilledRepeatedDocument.ValueC[1]), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	rootHash := []byte{0x16, 0xce, 0xc4, 0xa8, 0xb5, 0xf, 0xe4, 0xf4, 0x1a, 0x47, 0x4, 0xfa, 0xe0, 0x3f, 0x45, 0x7f, 0xad, 0x8e, 0x6b, 0x8e, 0x1c, 0xff, 0x2c, 0x7b, 0x47, 0x4f, 0xbb, 0x36, 0xc0, 0x74, 0xef, 0x70}
	assert.Equal(t, rootHash, doctree.rootHash)
	valid, err := ValidateProofSortedHashes(fieldHash, proof.SortedHashes, rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueC[1]")
	falseProof.Value = []byte{}
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateRepeatedSortedProofAutoSalts(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})

	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	_, err = doctree.CreateProof("InexistentField")
	assert.EqualError(t, err, "No such field: InexistentField in obj")

	proof, err := doctree.CreateProof("valueA")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.ExampleFilledRepeatedDocument.ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)

	fieldHash, err := CalculateHashForProofField(&proof, sha256Hash)
	valid, err := ValidateProofSortedHashes(fieldHash, proof.SortedHashes, doctree.rootHash, doctree.hash)
	assert.True(t, valid)

	valid, err = doctree.ValidateProof(&proof)
	assert.True(t, valid)
	assert.Nil(t, err)

	falseProof, err := doctree.CreateProof("valueA")
	falseProof.Value = []byte{}
	valid, err = doctree.ValidateProof(&falseProof)
	assert.False(t, valid)
	assert.EqualError(t, err, "Hash does not match")
}

func TestCreateProofFromRepeatedField(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})

	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueC[1].valueA")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueC[1].valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.ExampleFilledNestedRepeatedDocument.ValueC[1].ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)
}

func TestCreateProofFromRepeatedFieldWithParentPrefix(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, ParentPrefix: Property{Text: "doc"}, Salts: NewSaltForTest})

	assert.Equal(t, doctree.GetParentPrefix().ReadableName(), "doc")

	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("doc.valueC[1].valueA")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("doc.valueC[1].valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.ExampleFilledNestedRepeatedDocument.ValueC[1].ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)
}

func TestCreateProofFromNestedField(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})

	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("valueD.valueA.valueA")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("valueD.valueA.valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.ExampleFilledNestedRepeatedDocument.ValueD.ValueA.ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)
}

func TestCreateProofFromNestedFieldWithParentPrefix(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, ParentPrefix: Property{Text: "doc"}, Salts: NewSaltForTest})

	err := doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	proof, err := doctree.CreateProof("doc.valueD.valueA.valueA")
	assert.Nil(t, err)
	assert.Equal(t, ReadableName("doc.valueD.valueA.valueA"), proof.Property)
	assert.Equal(t, []byte(documentspb.ExampleFilledNestedRepeatedDocument.ValueD.ValueA.ValueA), proof.Value)
	assert.Equal(t, testSalt, proof.Salt)
}

func TestTree_AddLeaves_TwoLeafTree(t *testing.T) {
	// Leaf A: Hashed -- Leaf B: Hashed
	tree := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	hashLeafA := sha256.Sum256([]byte("leafA"))
	err := tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafB", 2), Hashed: true})
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	assert.NotEqual(t, hashLeafA[:], tree.RootHash())

	// Leaf A: Regular -- Leaf B: Hashed
	tree = NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA", 1), Salt: make([]byte, 32), Value: []byte{1}})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafB", 1), Hashed: true})
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	assert.NotEqual(t, hashLeafA[:], tree.RootHash())

	// Leaf A: Hashed -- Leaf B: Regular (hashed)
	tree = NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true})
	assert.Nil(t, err)
	leafB := LeafNode{Property: NewProperty("LeafB", 2), Salt: make([]byte, 32), Value: []byte{1}}
	leafB.HashNode(sha256.New(), false)
	err = tree.AddLeaf(leafB)
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	assert.NotEqual(t, hashLeafA[:], tree.RootHash())

	// Leaf A: Hashed -- Leaf B: Regular (no call to HashNode)
	tree = NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true})
	assert.Nil(t, err)
	leafB = LeafNode{Property: NewProperty("LeafB", 2), Salt: make([]byte, 32), Value: []byte{1}}
	err = tree.AddLeaf(leafB)
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	assert.NotEqual(t, hashLeafA[:], tree.RootHash())
}

func Test_Enums(t *testing.T) {
	// ExampleDocument is a protobuf message
	document := documentspb.ExampleDocument{
		Value1:      1,
		ValueA:      "Foo",
		ValueB:      "Bar",
		ValueBytes1: []byte("foobar"),
		EnumType:    documentspb.Enum_type_two,
	}

	doctree := NewDocumentTree(TreeOptions{Hash: sha256.New(), Salts: NewSaltForTest})
	doctree.AddLeavesFromDocument(&document)
	doctree.Generate()
	fmt.Printf("Generated tree: %s\n", doctree.String())

	for _, field := range []string{"valueA", "enum_type"} {
		proof, err := doctree.CreateProof(field)
		assert.NoError(t, err)
		proofJson, err := json.Marshal(proof)
		assert.NoError(t, err)
		fmt.Println("Proof:\n", string(proofJson))
		valid, err := doctree.ValidateProof(&proof)
		assert.NoError(t, err)
		assert.True(t, valid, "proof must be valid")
	}
}

func Test_integers(t *testing.T) {
	doc := new(documentspb.Integers)

	doctree := NewDocumentTree(TreeOptions{Hash: sha256.New(), Salts: NewSaltForTest})
	doctree.AddLeavesFromDocument(doc)
	doctree.Generate()
	fmt.Printf("Generated tree: %s\n", doctree.String())

	for _, field := range []string{"valueA", "valueB", "valueG", "valueH", "valueJ"} {
		proof, err := doctree.CreateProof(field)
		assert.NoError(t, err)
		proofJson, err := json.Marshal(proof)
		assert.NoError(t, err)
		fmt.Println("Proof:\n", string(proofJson))
		valid, err := doctree.ValidateProof(&proof)
		assert.NoError(t, err)
		assert.True(t, valid, "proof must be valid")
	}
}

func Test_GenerateSingleLeafTree(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	err := doctree.AddLeaf(
		LeafNode{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar1"},
			Hashed:   true,
		},
	)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	assert.Len(t, doctree.leaves, 1)
	assert.Equal(t, foobarHash[:], doctree.RootHash())
}

func Test_SaltMessage(t *testing.T) {
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(&documentspb.ExampleContainSaltsDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	assert.Len(t, doctree.leaves, 2)
	assert.Equal(t,doctree.leaves[0].Salt, []byte{0x1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x2}, "Salt should Match with the one contained in salt message")
	assert.Equal(t,doctree.leaves[1].Salt, []byte{0x3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x4}, "Salt should Match with the one contained in salt message")

	doctree2 := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	document := &documentspb.ExampleContainSaltsDocument
	document.Salts = nil
	err = doctree2.AddLeavesFromDocument(document)
	assert.Nil(t, err)
	err = doctree2.Generate()
	assert.Nil(t, err)
	assert.Len(t, doctree2.leaves, 2)
	for _, leaf := range doctree2.leaves {
		assert.NotNil(t, leaf.Salt)
	}
}

func Example_complete() {
	// ExampleDocument is a protobuf message
	document := documentspb.ExampleDocument{
		Value1:      1,
		ValueA:      "Foo",
		ValueB:      "Bar",
		ValueBytes1: []byte("foobar"),
	}

	doctree := NewDocumentTree(TreeOptions{Hash: sha256.New()})
	doctree.AddLeavesFromDocument(&document)
	doctree.Generate()
	fmt.Printf("Generated tree: %s\n", doctree.String())

	// Generate the actual proof for a field. In this case the field called "valueA".
	proof, _ := doctree.CreateProof("valueA")
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	// Validate the proof that was just generated
	valid, _ := doctree.ValidateProof(&proof)

	fmt.Printf("Proof validated: %v\n", valid)
}

func TestTree_LengthProp_ListMap(t *testing.T) {
	// length is 0
	doc := new(documentspb.SimpleEntries)
	tree := NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	err := tree.AddLeavesFromDocument(doc)
	assert.NoError(t, err)
	_, l := tree.GetLeafByProperty("entries.length")
	assert.Equal(t, l.Property.ReadableName(), "entries.length")
	expectedLen := 0
	el, err := toBytesArray(expectedLen)
	assert.NoError(t, err)
	assert.Equal(t, l.Value, el)

	// length is 1
	doc.Entries = append(doc.Entries, &documentspb.SimpleEntry{
		EntryKey:   "some key",
		EntryValue: "some value",
	})

	tree = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	err = tree.AddLeavesFromDocument(doc)
	assert.NoError(t, err)
	_, l = tree.GetLeafByProperty("entries.length")
	assert.Equal(t, l.Property.ReadableName(), "entries.length")
	expectedLen = 1
	el, err = toBytesArray(expectedLen)
	assert.NoError(t, err)
	assert.Equal(t, l.Value, el)
}

func TestTree_LengthProp_Map(t *testing.T) {
	// length is 0
	doc := new(documentspb.SimpleStringMap)
	tree := NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	err := tree.AddLeavesFromDocument(doc)
	assert.NoError(t, err)
	_, l := tree.GetLeafByProperty("value.length")
	assert.Equal(t, l.Property.ReadableName(), "value.length")
	expectedLen := 0
	el, err := toBytesArray(expectedLen)
	assert.NoError(t, err)
	assert.Equal(t, l.Value, el)

	// length is 1
	doc.Value = make(map[string]string)
	doc.Value["some key"] = "some value"
	tree = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	err = tree.AddLeavesFromDocument(doc)
	assert.NoError(t, err)
	_, l = tree.GetLeafByProperty("value.length")
	assert.Equal(t, l.Property.ReadableName(), "value.length")
	expectedLen = 1
	el, err = toBytesArray(expectedLen)
	assert.NoError(t, err)
	assert.Equal(t, l.Value, el)
}

func TestTree_LengthProp_List(t *testing.T) {
	// length is 0
	doc := new(documentspb.RepeatedItem)
	tree := NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	err := tree.AddLeavesFromDocument(doc)
	assert.NoError(t, err)
	_, l := tree.GetLeafByProperty("valueA.length")
	assert.Equal(t, l.Property.ReadableName(), "valueA.length")
	expectedLen := 0
	el, err := toBytesArray(expectedLen)
	assert.NoError(t, err)
	assert.Equal(t, l.Value, el)

	// length is 1
	doc.ValueA = append(doc.ValueA, &documentspb.SimpleItem{
		ValueA: "some string",
	})
	tree = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	err = tree.AddLeavesFromDocument(doc)
	assert.NoError(t, err)
	_, l = tree.GetLeafByProperty("valueA.length")
	assert.Equal(t, l.Property.ReadableName(), "valueA.length")
	expectedLen = 1
	el, err = toBytesArray(expectedLen)
	assert.NoError(t, err)
	assert.Equal(t, l.Value, el)

	leaves := tree.GetLeaves()
	assert.Len(t, leaves, 3)

}

func Test_GetSalt_Error(t *testing.T) {
	tree := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForErrorTest})
	err := tree.AddLeavesFromDocument(&documentspb.ExampleContainSaltsDocument)
	assert.EqualError(t, err, "error handling field ValueA: Cannot get salt")

	doc1 := new(documentspb.SimpleEntries)
	tree = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForErrorTest})
	err = tree.AddLeavesFromDocument(doc1)
	assert.EqualError(t, err, "error handling field Entries: Cannot get salt")

	doc2 := new(documentspb.RepeatedItem)
	tree = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForErrorTest})
	err = tree.AddLeavesFromDocument(doc2)
	assert.EqualError(t, err, "error handling field ValueA: Cannot get salt")
}

func Test_ReturnGeneratedSalts(t *testing.T) {
	doc := new (documentspb.ContainSalts)
	doc.ValueA = "TestA"
	doc.ValueB = 5
	assert.Nil(t, doc.Salts)
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(doc)
	assert.Nil(t, err)
	assert.Equal(t, len(doc.Salts), 2)
	err = doctree.Generate()
	assert.Nil(t, err)
	assert.Len(t, doctree.leaves, 2)
	hash1 := doctree.hash

	doctree2 := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	doc2 := new (documentspb.ContainSalts)
	doc2.ValueA = "TestA"
	doc2.ValueB = 5
	assert.Nil(t, doc2.Salts)
	doc2.Salts = doc.Salts
	err = doctree2.AddLeavesFromDocument(doc2)
	assert.Nil(t, err)
	err = doctree2.Generate()
	assert.Nil(t, err)
	hash2 := doctree2.hash

	assert.Equal(t, hash1, hash2)
}

func Test_MessageWithoutSaltsField(t *testing.T) {
	doc := new (documentspb.ExampleWithoutSalts)
	doc.ValueA = "TestA"
	doctree := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	err := doctree.AddLeavesFromDocument(doc)
	assert.EqualError(t, err, "Cannot find salts field in message")
}
