package proofs

import (
	"bytes"
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
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/xsleonard/go-merkle"
	"golang.org/x/crypto/blake2b"
)

var testSalt = []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225}

func NewSaltForTest(compact []byte) (salt []byte, err error) {
	return testSalt, nil
}

func NewSaltForErrorTest(compact []byte) (salt []byte, err error) {
	return nil, errors.New("Cannot get salt")
}

var sha256Hash = sha256.New()
var blake2bHash, _ = blake2b.New512([]byte{1, 2, 3, 4})

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
		Salt:     []byte{1}, // Invalid salt length, must be either 0 or 32 bytes
	}
	err = invalidSaltLeaf.HashNode(h, false)
	assert.EqualError(t, err, "fieldName: Salt has incorrect length: 1 instead of 32")
	err = invalidSaltLeaf.HashNode(h, true)
	assert.EqualError(t, err, "[42]: Salt has incorrect length: 1 instead of 32")

}

func TestTree_Generate(t *testing.T) {
	protoMessage := documentspb.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}

	leaves, err := FlattenMessage(&protoMessage, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DisableHashLeaves: true})
	var hashes [][]byte
	assert.Equal(t, 12, len(leaves))
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}

	assert.NoError(t, tree.Generate(hashes, sha256Hash))
	h := tree.Root().Hash
	expectedHash := []byte{0xaf, 0x15, 0x46, 0x42, 0x95, 0xc8, 0x50, 0x46, 0x9c, 0x6e, 0x1a, 0xdc, 0xc, 0x57, 0x53, 0x63, 0xf0, 0xce, 0xb9, 0x9a, 0x50, 0x3, 0x70, 0xaa, 0x65, 0xce, 0x28, 0xb0, 0x91, 0x80, 0xb, 0x13}
	assert.Equal(t, expectedHash, h, "Hash should match")
}

func TestSortedHashTree_Generate(t *testing.T) {
	protoMessage := documentspb.ExampleDocument{
		ValueA: "Foo",
		ValueB: "Bar",
	}

	leaves, err := FlattenMessage(&protoMessage, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	tree := merkle.NewTreeWithOpts(merkle.TreeOptions{DisableHashLeaves: true, EnableHashSorting: true})
	var hashes [][]byte
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}
	assert.NoError(t, tree.Generate(hashes, sha256Hash))
	h := tree.Root().Hash
	expectedHash := []byte{0x60, 0xdd, 0xfc, 0x7d, 0x8f, 0x58, 0xd5, 0xe6, 0x94, 0xce, 0x2c, 0x2a, 0x30, 0x7, 0xe0, 0x45, 0x86, 0xfb, 0x67, 0x8a, 0x79, 0x73, 0xc7, 0x60, 0x55, 0x80, 0xb5, 0x9c, 0xdd, 0x54, 0xe3, 0xf9}
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.EqualError(t, err, "tree already filled")
}

// Test DocumentTree sets rootHash correctly and validated the generated Proof
func TestDocumentTree_WithRootHash(t *testing.T) {
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
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
	doctreeWithRootHash, err := NewDocumentTreeWithRootHash(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest}, expectedRootHash)
	assert.Nil(t, err)
	assert.Equal(t, expectedRootHash, doctreeWithRootHash.rootHash)

	valid, err = doctreeWithRootHash.ValidateProof(&proof)
	assert.Nil(t, err)
	assert.True(t, valid)
}

// TestTree_hash tests calculating hashes both with sha256 and md5
func TestTree_hash(t *testing.T) {
	// MD5
	hashFuncMd5 := md5.New()
	doctree, err := NewDocumentTree(TreeOptions{Hash: hashFuncMd5, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)

	expectedRootHash := []byte{0xea, 0xa2, 0x2c, 0xc4, 0x1b, 0x91, 0x96, 0x23, 0x66, 0xc6, 0xa0, 0x8f, 0xaa, 0x49, 0xc0, 0xe8}
	assert.Equal(t, expectedRootHash, doctree.rootHash)

	// No hash func set
	doctreeNoHash, err := NewDocumentTree(TreeOptions{Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctreeNoHash.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "hash is not set")

	// SHA256
	doctreeSha256, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctreeSha256.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)
	err = doctreeSha256.Generate()
	expectedRootHash = []byte{0xe1, 0xee, 0x59, 0x40, 0xb8, 0x2c, 0x2b, 0xb4, 0x44, 0xa0, 0x4e, 0xe2, 0x3, 0x87, 0x27, 0xe8, 0x3a, 0xaa, 0xfd, 0xb0, 0x77, 0x70, 0x56, 0x5a, 0x5c, 0x40, 0xb3, 0x57, 0x14, 0x3d, 0xf0, 0xb5}
	assert.Equal(t, expectedRootHash, doctreeSha256.rootHash)
}

func TestTree_AddLeaf_hashed(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeaf(
		LeafNode{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar1", Compact: []byte{1}},
			Hashed:   true,
		},
	)
	assert.Nil(t, err)
	err = doctree.AddLeaf(
		LeafNode{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar2", Compact: []byte{2}},
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeaves([]LeafNode{
		{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar1", Compact: []byte{1}},
			Hashed:   true,
		},
		{
			Hash:     foobarHash[:],
			Property: Property{Text: "Foobar2", Compact: []byte{2}},
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	length := len(doctree.leaves)
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.EqualError(t, err, "duplicated leaf")
	assert.Equal(t, length, len(doctree.leaves))
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

func TestTree_GenerateStandardProof(t *testing.T) {
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
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
	doctreeA, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctreeA.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
	assert.Nil(t, err)

	err = doctreeA.Generate()
	assert.NoError(t, err)

	doctreeB, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
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

	expectedRootHashB := []byte{0xd9, 0x5b, 0x15, 0xf8, 0xbb, 0xc0, 0x79, 0x35, 0x65, 0x5a, 0xe9, 0x3d, 0x88, 0xa0, 0xad, 0x2a, 0x90, 0x6, 0x53, 0x35, 0x88, 0x6c, 0xd8, 0x6f, 0xb1, 0xce, 0x93, 0x6f, 0x86, 0x98, 0x2c, 0xfe}
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
	doctreeA, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctreeA.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
	assert.Nil(t, err)

	err = doctreeA.Generate()
	assert.Nil(t, err)

	doctreeB, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
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

	expectedRootHashB := []byte{0xe3, 0x24, 0x36, 0x74, 0x5, 0x43, 0x19, 0x2b, 0xf2, 0x59, 0x72, 0xa7, 0x7f, 0xaf, 0x1a, 0xbf, 0x37, 0x42, 0x2f, 0xe1, 0xf4, 0xd7, 0x61, 0xf9, 0x3, 0x55, 0xf9, 0x13, 0xb7, 0xb9, 0x8d, 0x4c}
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	hashA := sha256.Sum256([]byte("A"))
	hashB := sha256.Sum256([]byte("B"))
	hashC := sha256.Sum256([]byte("C"))
	hashD := sha256.Sum256([]byte("D"))

	err = doctree.AddLeaves([]LeafNode{
		{
			Property: Property{Text: "A", Compact: []byte{1}},
			Hash:     hashA[:],
			Hashed:   true,
		},
		{
			Property: Property{Text: "B", Compact: []byte{2}},
			Hash:     hashB[:],
			Hashed:   true,
		},
		{
			Property: Property{Text: "C", Compact: []byte{3}},
			Hash:     hashC[:],
			Hashed:   true,
		},
		{
			Property: Property{Text: "D", Compact: []byte{4}},
			Hash:     hashD[:],
			Hashed:   true,
		},
	})
	assert.NoError(t, err)

	err = doctree.Generate()
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	doc := documentspb.FilledExampleDocument
	doc.ValueNotHashed = sha256Hash.Sum([]byte("some hash"))
	doc.ValueBytes1 = []byte("ValueBytes1")
	err = doctree.AddLeavesFromDocument(&doc)
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
	rootHash := []byte{0x8d, 0xb4, 0x0, 0xfe, 0x35, 0x17, 0xf0, 0x23, 0xa3, 0xe7, 0x29, 0xa, 0x8b, 0x92, 0x5e, 0x1b, 0xde, 0xee, 0x47, 0xe8, 0x81, 0x93, 0x3e, 0xfe, 0x7f, 0x27, 0x6a, 0x90, 0x6f, 0x6d, 0x84, 0x28}
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	doc := documentspb.FilledExampleDocument
	doc.ValueNotHashed = sha256Hash.Sum([]byte("some hash"))
	doc.ValueBytes1 = []byte("ValueBytes1")
	err = doctree.AddLeavesFromDocument(&doc)
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
	rootHash := []byte{0x8d, 0xb4, 0x0, 0xfe, 0x35, 0x17, 0xf0, 0x23, 0xa3, 0xe7, 0x29, 0xa, 0x8b, 0x92, 0x5e, 0x1b, 0xde, 0xee, 0x47, 0xe8, 0x81, 0x93, 0x3e, 0xfe, 0x7f, 0x27, 0x6a, 0x90, 0x6f, 0x6d, 0x84, 0x28}
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
	doctree, err = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, CompactProperties: true, Salts: NewSaltForTest})
	assert.Nil(t, err)
	doc := documentspb.FilledExampleDocument
	doc.ValueBytes1 = []byte("ValueBytes1")
	err = doctree.AddLeavesFromDocument(&doc)
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
	rootHash := []byte{0xfa, 0x54, 0x43, 0x87, 0xc7, 0x3c, 0x64, 0xc9, 0x77, 0x6a, 0x9a, 0x9a, 0x79, 0xb2, 0xdf, 0xa, 0x71, 0x71, 0xd0, 0xfc, 0x14, 0xf0, 0xbd, 0x45, 0x48, 0x50, 0xb4, 0x36, 0xf2, 0xac, 0xe3, 0x46}
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleOneofSampleDocument)
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

	doctree, err = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.OneofSample{
		OneofBlock: &documentspb.OneofSample_ValueC{"bor"},
	})
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("valueB")
	assert.EqualError(t, err, "No such field: valueB in obj")
	_, err = doctree.CreateProof("valueC")
	assert.Nil(t, err)

	doctree, err = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.OneofSample{
		OneofBlock: &documentspb.OneofSample_ValueD{&documentspb.SimpleItem{ValueA: "testA"}},
	})
	assert.Nil(t, err)
	err = doctree.Generate()

	_, err = doctree.CreateProof("valueC")
	assert.EqualError(t, err, "No such field: valueC in obj")
	_, err = doctree.CreateProof("valueD.valueA")
	assert.Nil(t, err)

	doctree, err = NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.FilledExampleDocument)
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
	rootHash := []byte{0x54, 0x96, 0x85, 0x35, 0x65, 0x12, 0xb8, 0x63, 0x30, 0x51, 0xb5, 0x1f, 0x79, 0x99, 0x5a, 0x9a, 0x34, 0xc9, 0x34, 0x69, 0xa2, 0xb4, 0xd9, 0xca, 0x7a, 0x4c, 0x1f, 0x8e, 0xeb, 0x73, 0x6f, 0x74}
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledRepeatedDocument)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, ParentPrefix: Property{Text: "doc"}, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
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
	doctree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256Hash, ParentPrefix: Property{Text: "doc"}, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleFilledNestedRepeatedDocument)
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
	tree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	hashLeafA := sha256.Sum256([]byte("leafA"))
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafB", 2), Hashed: true})
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	assert.NotEqual(t, hashLeafA[:], tree.RootHash())

	// Leaf A: Regular -- Leaf B: Hashed
	tree, err = NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA", 1), Salt: make([]byte, 32), Value: []byte{1}})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafB", 2), Hashed: true})
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	assert.NotEqual(t, hashLeafA[:], tree.RootHash())

	// Leaf A: Hashed -- Leaf B: Regular (hashed)
	tree, err = NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true})
	assert.Nil(t, err)
	leafB := LeafNode{Property: NewProperty("LeafB", 2), Salt: make([]byte, 32), Value: []byte{1}}
	assert.NoError(t, leafB.HashNode(sha256.New(), false))
	err = tree.AddLeaf(leafB)
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	assert.NotEqual(t, hashLeafA[:], tree.RootHash())

	// Leaf A: Hashed -- Leaf B: Regular (no call to HashNode)
	tree, err = NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
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

	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	assert.NoError(t, doctree.AddLeavesFromDocument(&document))
	assert.NoError(t, doctree.Generate())
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	assert.NoError(t, doctree.AddLeavesFromDocument(doc))
	assert.NoError(t, doctree.Generate())

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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = doctree.AddLeaf(
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
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.ExampleContainSaltsDocument)
	assert.Nil(t, err)
	err = doctree.Generate()
	assert.Nil(t, err)
	assert.Len(t, doctree.leaves, 2)
	assert.Equal(t, doctree.leaves[0].Salt, []byte{0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2}, "Salt should Match with the one contained in salt message")
	assert.Equal(t, doctree.leaves[1].Salt, []byte{0x3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x4}, "Salt should Match with the one contained in salt message")

	doctree2, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
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
		Name: &documentspb.Name{
			First: "Foo",
			Last:  "Bar",
		},
	}

	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256.New(), LeafHash: md5.New()})
	if err != nil {
		panic(err)
	}

	err = doctree.AddLeavesFromDocument(&document)
	if err != nil {
		panic(err)
	}

	err = doctree.Generate()
	if err != nil {
		panic(err)
	}

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
	tree, err := NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	assert.Nil(t, err)
	err = tree.AddLeavesFromDocument(doc)
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

	tree, err = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	assert.Nil(t, err)
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
	tree, err := NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	assert.Nil(t, err)
	err = tree.AddLeavesFromDocument(doc)
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
	tree, err = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	assert.Nil(t, err)
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
	tree, err := NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	assert.Nil(t, err)
	err = tree.AddLeavesFromDocument(doc)
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
	tree, err = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New()})
	assert.Nil(t, err)
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
	tree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForErrorTest})
	assert.Nil(t, err)
	err = tree.AddLeavesFromDocument(&documentspb.ExampleContainSaltsDocument)
	assert.EqualError(t, err, "error handling field ValueA: Cannot get salt")

	doc1 := new(documentspb.SimpleEntries)
	tree, err = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForErrorTest})
	assert.Nil(t, err)
	err = tree.AddLeavesFromDocument(doc1)
	assert.EqualError(t, err, "error handling field Entries: Cannot get salt")

	doc2 := new(documentspb.RepeatedItem)
	tree, err = NewDocumentTree(TreeOptions{CompactProperties: true, EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForErrorTest})
	assert.Nil(t, err)
	err = tree.AddLeavesFromDocument(doc2)
	assert.EqualError(t, err, "error handling field ValueA: Cannot get salt")
}

func Test_ReturnGeneratedSalts(t *testing.T) {
	doc := new(documentspb.ContainSalts)
	doc.ValueA = "TestA"
	doc.ValueB = 5
	assert.Nil(t, doc.Salts)
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(doc)
	assert.Nil(t, err)
	assert.Equal(t, len(doc.Salts), 2)
	err = doctree.Generate()
	assert.Nil(t, err)
	assert.Len(t, doctree.leaves, 2)
	hash1 := doctree.hash

	doctree2, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	doc2 := new(documentspb.ContainSalts)
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
	doc := new(documentspb.ExampleWithoutSalts)
	doc.ValueA = "TestA"
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(doc)
	assert.EqualError(t, err, "Cannot find salts field in message")
}

func TestTree_AddTwoLeavesWithSameReadableName(t *testing.T) {

	tree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	hashLeafA := sha256.Sum256([]byte("leafA"))
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 2), Hashed: true})
	assert.EqualError(t, err, "duplicated leaf")

	tree2, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = tree2.AddLeaves([]LeafNode{LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true},
		LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 2), Hashed: true}})

	assert.EqualError(t, err, "duplicated leaf")
}

func TestTree_AddTwoLeavesWithSameCompactName(t *testing.T) {

	tree, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	hashLeafA := sha256.Sum256([]byte("leafA"))
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafB", 1), Hashed: true})
	assert.EqualError(t, err, "duplicated leaf")

	tree2, err := NewDocumentTree(TreeOptions{EnableHashSorting: true, Hash: sha256.New(), Salts: NewSaltForTest})
	assert.Nil(t, err)
	err = tree2.AddLeaves([]LeafNode{LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafA", 1), Hashed: true},
		LeafNode{Hash: hashLeafA[:], Property: NewProperty("LeafB", 1), Hashed: true}})

	assert.EqualError(t, err, "duplicated leaf")
}

func TestTree_TooLongStringAndBytes(t *testing.T) {
	doc := new(documentspb.ExampleWithPaddingField)
	doc.ValueA = "TestATestATestATestATestATestATestATestATestA"
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(doc)
	assert.EqualError(t, err, "error handling field ValueA: Field's length 45 is bigger than 32")

	doc2 := new(documentspb.ExampleWithPaddingField)
	doc2.ValueA = "TestA"
	doc2.ValueB = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 1, 1}
	doctree2, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	err = doctree2.AddLeavesFromDocument(doc2)
	assert.EqualError(t, err, "error handling field ValueB: Field's length 33 is bigger than 32")
}

func TestTree_PaddingSucess(t *testing.T) {
	doc := new(documentspb.ExampleWithPaddingField)
	doc.ValueA = "TestA"
	doc.ValueB = []byte{1, 2, 3}
	padding := bytes.Repeat([]byte{0}, 32-len(doc.ValueA))
	padding2 := bytes.Repeat([]byte{0}, 32-len(doc.ValueB))
	//right padding
	doctree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	err = doctree.AddLeavesFromDocument(doc)
	assert.Nil(t, err)
	leaves := doctree.GetLeaves()
	assert.Equal(t, leaves[0].Value, append([]byte(doc.ValueA), padding...))
	assert.Equal(t, leaves[1].Value, append(doc.ValueB, padding2...))
	//left padding
	doctree2, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, FixedLengthFieldLeftPadding: true})
	assert.Nil(t, err)
	err = doctree2.AddLeavesFromDocument(doc)
	assert.Nil(t, err)
	leaves = doctree2.GetLeaves()
	assert.Equal(t, leaves[0].Value, append(padding, []byte(doc.ValueA)...))
	assert.Equal(t, leaves[1].Value, append(padding2, doc.ValueB...))

	//no padding
	doc2 := new(documentspb.ExampleWithPaddingField)
	doc2.ValueA = "TestATestATestATestATestATestABB"
	doc2.ValueB = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0}

	doctree3, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, FixedLengthFieldLeftPadding: true})
	assert.Nil(t, err)
	err = doctree3.AddLeavesFromDocument(doc2)
	assert.Nil(t, err)
	leaves = doctree3.GetLeaves()
	assert.Equal(t, leaves[0].Value, []byte(doc2.ValueA))
	assert.Equal(t, leaves[1].Value, doc2.ValueB)

	doctree4, err := NewDocumentTree(TreeOptions{Hash: sha256Hash})
	assert.Nil(t, err)
	err = doctree4.AddLeavesFromDocument(doc2)
	assert.Nil(t, err)
	leaves = doctree4.GetLeaves()
	assert.Equal(t, leaves[0].Value, []byte(doc2.ValueA))
	assert.Equal(t, leaves[1].Value, doc2.ValueB)
}

func TestTree_ToomanyLeaves(t *testing.T) {
	tree, err := NewDocumentTree(TreeOptions{Salts: NewSaltForTest, TreeDepth: 3})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA1", 1)})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA2", 2)})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA3", 3)})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA4", 4)})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA5", 5)})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA6", 6)})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA7", 7)})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA8", 8)})
	assert.Nil(t, err)

	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA9", 9)})
	assert.EqualError(t, err, "tree already has enough leaves")
}

func TestTree_TreeDepthArg(t *testing.T) {
	_, err := NewDocumentTree(TreeOptions{Salts: NewSaltForTest, TreeDepth: 33})
	assert.EqualError(t, err, "TreeDepth is too bigger, it should not be bigger than 32")

	_, err = NewDocumentTreeWithRootHash(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest, TreeDepth: 33}, nil)
	assert.EqualError(t, err, "TreeDepth is too bigger, it should not be bigger than 32")

	_, err = NewDocumentTree(TreeOptions{Salts: NewSaltForTest, TreeDepth: 32})
	assert.Nil(t, err)
}

func TestTree_EmptyLeavesAdded(t *testing.T) {
	tree, err := NewDocumentTree(TreeOptions{Hash: sha256Hash, Salts: NewSaltForTest, TreeDepth: 3})
	assert.Nil(t, err)
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA1", 1), Salt: testSalt})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA2", 2), Salt: testSalt})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA3", 3), Salt: testSalt})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA4", 4), Salt: testSalt})
	err = tree.AddLeaf(LeafNode{Property: NewProperty("LeafA5", 5), Salt: testSalt})
	assert.Nil(t, err)
	err = tree.Generate()
	assert.Nil(t, err)
	leaves := tree.GetLeaves()
	assert.Len(t, leaves, 8)
}

func TestTree_Blake2b512LeafSha256InternalHashFunction(t *testing.T) {
	doctree, err := NewDocumentTree(TreeOptions{
		Hash:     sha256Hash,
		LeafHash: blake2bHash,
		Salts:    NewSaltForTest,
	})
	assert.Nil(t, err)

	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)

	//leaf should hashed by Blake2b
	for _, leaf := range doctree.GetLeaves() {
		hashByInternal := leaf.Hash
		assert.Len(t, leaf.Hash, 64, "length of blake2b512 hash is 64")
		leaf.Hash = []byte{}
		leaf.Hashed = false
		leaf.HashNode(blake2bHash, false)
		assert.Equal(t, hashByInternal, leaf.Hash)
	}

	err = doctree.Generate()
	assert.Nil(t, err)

	rootHash := doctree.rootHash
	assert.Len(t, rootHash, 32, "length of sha256 hash is 32")

	expectedHash := []byte{0x1, 0xe1, 0xe7, 0x59, 0x2a, 0xf5, 0xba, 0xa3, 0xbc, 0x5a, 0x3f, 0xb0, 0x82, 0xd4, 0xa1, 0x76, 0xad, 0xc3, 0x8b, 0x52, 0x4a, 0x68, 0xc, 0x30, 0x37, 0x3a, 0xda, 0xda, 0x9a, 0x41, 0xd6, 0xe0}
	assert.Equal(t, expectedHash, rootHash, "Hash should match")
	proof, err := doctree.CreateProof("value0")
	assert.Nil(t, err)

	valid, err := doctree.ValidateProof(&proof)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_Sha256LeafBlake2b512InternalHashFunction(t *testing.T) {
	doctree, err := NewDocumentTree(TreeOptions{
		Hash:     blake2bHash,
		LeafHash: sha256Hash,
		Salts:    NewSaltForTest,
	})
	assert.Nil(t, err)

	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)

	//leaf should hashed by sha256
	for _, leaf := range doctree.GetLeaves() {
		hashByInternal := leaf.Hash
		assert.Len(t, leaf.Hash, 32, "length of sha256 hash is 32")
		leaf.Hash = []byte{}
		leaf.Hashed = false
		leaf.HashNode(sha256Hash, false)
		assert.Equal(t, hashByInternal, leaf.Hash)
	}

	err = doctree.Generate()
	assert.Nil(t, err)

	rootHash := doctree.rootHash
	assert.Len(t, rootHash, 64, "length of Blake2b512 hash is 64")

	expectedHash := []byte{0x7f, 0x63, 0x55, 0x32, 0x9f, 0x35, 0x8a, 0x5f, 0xdc, 0x54, 0x7a, 0xbb, 0x38, 0x3d, 0x8f, 0x3b, 0xe7, 0x66, 0x17, 0x12, 0xaa, 0x82, 0xb4, 0x7d, 0x50, 0xdf, 0x19, 0xd0, 0x90, 0xad, 0x6b, 0x4a, 0x86, 0xdd, 0x7f, 0x65, 0xbb, 0x9c, 0xbc, 0x91, 0x48, 0xe6, 0xf9, 0x42, 0x63, 0xdb, 0x73, 0x8d, 0x7d, 0xd9, 0x3f, 0xd, 0x2a, 0xb7, 0x44, 0x7a, 0xce, 0x47, 0x94, 0xe1, 0x15, 0xeb, 0xa7, 0x9f}
	assert.Equal(t, expectedHash, rootHash, "Hash should match")
	proof, err := doctree.CreateProof("value0")
	assert.Nil(t, err)

	valid, err := doctree.ValidateProof(&proof)
	assert.Nil(t, err)
	assert.True(t, valid)
}

func TestTree_GenerateLeafSha256NodeBlake2b(t *testing.T) {
	doctree, err := NewDocumentTree(TreeOptions{
		Hash:     blake2bHash,
		LeafHash: sha256Hash,
		Salts:    NewSaltForTest,
	})
	assert.NoError(t, err)
	err = doctree.AddLeavesFromDocument(&documentspb.LongDocumentExample)
	assert.Nil(t, err)

	err = doctree.Generate()
	assert.Nil(t, err)

	rootHash := doctree.rootHash
	assert.Len(t, rootHash, 64, "length of Blake2b512 hash is 64")

	assert.Len(t, doctree.leaves, 15)

	leafHash := doctree.leaves[0].Hash
	assert.Len(t, leafHash, 32, "length of sha256 hash is 32")
}
