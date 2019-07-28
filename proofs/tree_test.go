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
	proofspb "github.com/centrifuge/precise-proofs/proofs/proto"
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
	tree := merkle.NewTree(sha256Hash)
	var hashes [][]byte
	assert.Equal(t, 12, len(leaves))
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}

	assert.NoError(t, tree.Generate(hashes, 0))
	h := tree.RootHash()
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
	tree := merkle.NewTreeWithHashSortingEnable(sha256Hash)
	var hashes [][]byte
	for _, leaf := range leaves {
		hashes = append(hashes, leaf.Hash)
	}
	assert.NoError(t, tree.Generate(hashes, 0))
	h := tree.RootHash()
	expectedHash := []byte{0x60, 0xdd, 0xfc, 0x7d, 0x8f, 0x58, 0xd5, 0xe6, 0x94, 0xce, 0x2c, 0x2a, 0x30, 0x7, 0xe0, 0x45, 0x86, 0xfb, 0x67, 0x8a, 0x79, 0x73, 0xc7, 0x60, 0x55, 0x80, 0xb5, 0x9c, 0xdd, 0x54, 0xe3, 0xf9}
	assert.Equal(t, expectedHash, h, "Hash should match")
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
	fieldHash := doctree.leaves[0].Hash
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
	fieldHash := doctree.leaves[0].Hash
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

	fieldHash := doctreeA.leaves[0].Hash
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

	fieldHash = doctreeA.leaves[0].Hash
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

	fieldHash := doctreeA.leaves[0].Hash
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

	fieldHash = doctreeA.leaves[0].Hash
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
	fieldHash := doctree.leaves[0].Hash
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
	fieldHash := doctree.leaves[0].Hash
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
	fieldHash := doctree.leaves[0].Hash
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
	fieldHash := doctree.leaves[0].Hash
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

	// Fixed Size Tree
	doctree, err = NewDocumentTree(TreeOptions{Hash: sha256.New(), LeafHash: md5.New(), TreeDepth: 32})
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

	fmt.Printf("Generated fixed size tree: %s\n", doctree.String())

	// Generate the actual proof for a field. In this case the field called "valueA".
	proof, _ = doctree.CreateProof("valueA")
	proofJson, _ = json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	// Validate the proof that was just generated
	valid, _ = doctree.ValidateProof(&proof)

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
	tree, err := NewDocumentTree(TreeOptions{Salts: NewSaltForTest, TreeDepth: 3, Hash: sha256Hash})
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

	_, err = NewDocumentTree(TreeOptions{Salts: NewSaltForTest, TreeDepth: 32, Hash: sha256Hash})
	assert.Nil(t, err)
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

func TestTree_FixedSizeTreeDoNotSupportSortingByHash(t *testing.T) {
	_, err := NewDocumentTree(TreeOptions{
		Hash:              blake2bHash,
		LeafHash:          sha256Hash,
		Salts:             NewSaltForTest,
		EnableHashSorting: true,
		TreeDepth:         256,
	})
	assert.Equal(t, "Fixed size tree does not support sorting by hash", err.Error())
}

func TestOptimizeProofs(t *testing.T) {
	// nil input
	opt, err := OptimizeProofs(nil, nil, sha256.New())
	assert.NoError(t, err)
	assert.Empty(t, opt)

	// empty input
	var original []*proofspb.Proof
	opt, err = OptimizeProofs(original, nil, sha256.New())
	assert.NoError(t, err)
	assert.Empty(t, opt)

	// sample proofPayload
	payload := `
{
  "header": {
    "document_root":"0x7eba2627f27e0c2b49cd7f3aee6a11ca2637e1e07d5bb82b68253e7905ca074c"
  },
  "field_proofs": [
    {
      "property": "0x000100000000000e",
      "value": "0x007b0000000000000000",
      "salt": "0x3d9f77a675dbc27641b27d8bbf612164774adc814a40d3c1324c5c77b26f9aa2",
      "hash": "0x",
      "sorted_hashes": [
        "0xd42948fa37dd912117ac5966b55d4b364005e4dc366e3afb6caf38649dce7d20",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x000100000000000d",
      "value": "0x455552",
      "salt": "0xcc8a2c1e741a708995d38288d84515df9cb67a52e015d6e73a9cbb6217f4c476",
      "hash": "0x",
      "sorted_hashes": [
        "0x07b97ffc8aaf85fffa15cec19f509f876d26af31a3186af35d4672b05f8a5310",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
		{
      "property": "0x0001000000000016",
      "value": "0x000000005c9ca876",
      "salt": "0x4a706b3d95476cef89beba9dee5cd0b1fa4cdc91296bce089bed4b92263bc9f0",
      "hash": "0x",
      "sorted_hashes": [
        "0xfb2b62df3ef2783f2e27ebe1a58aeb6a5e0915c4ced901bd85288d6fb144a02c",
        "0x0d2a959865cbb523021c642d37a8c018eba07782357d055a361e4ec769c500e1",
        "0x775dd58168d7b778197f0d5eab357647cd27ab91706b7f5acbc86bb33f84daf9",
        "0x3e76163beecf850fd051fda774d06d2963303721d1eb25fcb56f5dfa6b9f0add",
        "0x17e476077dde0a65139b094cff2c2bde82c2bf38c08299f28643074d117f967a",
        "0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
        "0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x0001000000000013",
      "value": "0xc0338705d374f72ebc1b27854ec1152337ff12fb",
      "salt": "0xef821a1c720b7f283077fe52a80db4f73db5932744b78ad7ca29e6069d4f5d84",
      "hash": "0x",
      "sorted_hashes": [
        "0xacddc0b566bd952cb74998348e23c3061d9a504d807b5cec80d21307c70e3467",
        "0xee3a6581c1c3102b6a17b5f269716a2081606103d05f0bfdbbdf5b7639613302",
        "0xc3de7ef9786ca87dfd8373afcd98c536c838c462526ee5c092d76867c2ce15af",
        "0x3e76163beecf850fd051fda774d06d2963303721d1eb25fcb56f5dfa6b9f0add",
        "0x17e476077dde0a65139b094cff2c2bde82c2bf38c08299f28643074d117f967a",
        "0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
        "0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x0001000000000002",
      "value": "0x756e70616964",
      "salt": "0xde3711a205db1b5b2b28f410dd6bcfb6a68da799f2c13a70e0b8eae30194dbfa",
      "hash": "0x",
      "sorted_hashes": [
        "0x8007b147695dfb7e5981a097a1213df1ebc12606c6313ca53cd35a7989bf4e60",
        "0xaf19c8d425eb7cae7b6c2f948636ebc3297babd49f6194385aed04759c5f1b33",
        "0xe2da7185358359ea3666be334f8f7223f8f96a6c094b1c52e461644384aaceb6",
        "0xd4c21ca487bd4101b62e1292db9f547e670a91ed4555acb06a0e0b25ecd403ad",
        "0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
        "0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
        "0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x040000000000000a",
      "value": "0x",
      "salt": "0x",
      "hash": "0xca87e9ba4fcfc9eb27594e18d14dc3fb094913e67c9aa3f19e0e3205dbb7dbfa",
      "sorted_hashes": [
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x0300000000000001c0338705d374f72ebc1b27854ec1152337ff12fb000000000000000000000000746c4d8464ad40caadc76c2c0b31393c6ae0d6c500000004",
      "value": "0xa2776063c2177a8e4be999fd337d939d03df0f341c50d2dac45dafad0008016e248cfb0076035c514dfc66af39e574bcc795a6af6b112a6ec90ff9291c766b7c01",
      "salt": "0x6cfd93297f2be442bfbb7d9c8b8598e876f9ebafe9f098ef790203de3bfbbf3c",
      "hash": "0x",
      "sorted_hashes": [
        "0x179b3819d3b2a17be17401b78b350e79b6c70e4b67803eb398221b12879ff720",
        "0xab8e27cb3d33491409524c36b9c4a9afce4eee70b0ffc576c4e09dff928231a1",
        "0xca87e9ba4fcfc9eb27594e18d14dc3fb094913e67c9aa3f19e0e3205dbb7dbfa"
      ]
    },
		{
      "property": "0x0100000000000004",
      "value": "0x563928f23599499286e138d185d49af9d2d69b7d291499124ddbecf95533acc8",
      "salt": "0xcdce11607a4008de202a3d0aea684f812e0ec6f45c7a8a904b98214d2c042bf4",
      "hash": "0x",
      "sorted_hashes": [
        "0x2f57c3d607effeac903b45ece78c569edd2f7a59defa1d806823f61d4495e435",
        "0xc52a2036ab698ae068589bc78c50b7ed48a9d8c86f4c9a7c404980c0226c1099",
        "0x14c175413ed3a91e23fd831235885f7652b78c16e2a86328dd2d8b5adc39cc00",
        "0xdc6ea84837c32ed666d580e7dfb47305e670bd2d5b81c3a1bced33d00a2de749",
        "0xc07430e27007ac41e71f4efa61fbc8141c4220bbe06ae570179aa403d144b1dd",
        "0x428df21c9bae763a91f93587847a596b8e3a77bcbe51c7f218fa3b33906279ec",
        "0x6cff4b5e8568c9d8b612c7dedefbad0553db5da9e9abb4b897a43e28fb43360d",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x0100000000000014e821d1b50945ff736992d0af793684dd53ac7fa7000000000000000000000000",
      "value": "0xfc03d8fc2094952d153396f1904513850b4f76fcfeaef9c44dcb6d7de1921674",
      "salt": "0x200d4ab58a902b0f5b860cf04ef19ea3c40113558c2a3858da583ebf76b4fc74",
      "hash": "0x",
      "sorted_hashes": [
        "0x1729e97cc44f4d0f3930175d1b29a1d0c3d217a244a98be549f72d69bc35f2ef",
        "0x1d200bb5e4a0935bb392e560398cc4f09ef8a47ce5b60ffb8561f9649b227348",
        "0x272cf01f0c371697319e95ffade01a221ed60a2fea530d1f252f0966b868157d",
        "0x8e32d7a9533edbb5fe0af56b58a081adf56fdcc084d7b870ee76099c57f056cc",
        "0x344c38025b6398676c1014205c69e6c391dd986f1a1e6c9337e7ac1b9daac2f7",
        "0x428df21c9bae763a91f93587847a596b8e3a77bcbe51c7f218fa3b33906279ec",
        "0x6cff4b5e8568c9d8b612c7dedefbad0553db5da9e9abb4b897a43e28fb43360d",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x01000000000000130000000000000001000000020000000000000000",
      "value": "0x88c5386e0c2a5a5444aca7b06a37192d6a65b43687280111a0b898f158e7b5ad",
      "salt": "0x9f2e31427e1ea4b79b42bbe7f5ab5d3f433aa5a9f88d6d4466f40ccfa037a9b7",
      "hash": "0x",
      "sorted_hashes": [
        "0x6ca76bc69b524a95d284a7bdb16f4926301b91541c95688a71b6fff815b328c6",
        "0x608bbd5ba0e29a1506780c594e2de85e0a62e7ea8c9d7bdbd2e4a6cced40b5ce",
        "0x272cf01f0c371697319e95ffade01a221ed60a2fea530d1f252f0966b868157d",
        "0x8e32d7a9533edbb5fe0af56b58a081adf56fdcc084d7b870ee76099c57f056cc",
        "0x344c38025b6398676c1014205c69e6c391dd986f1a1e6c9337e7ac1b9daac2f7",
        "0x428df21c9bae763a91f93587847a596b8e3a77bcbe51c7f218fa3b33906279ec",
        "0x6cff4b5e8568c9d8b612c7dedefbad0553db5da9e9abb4b897a43e28fb43360d",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x0100000000000013000000000000000100000004",
      "value": "0x0000000000000002",
      "salt": "0x08528f14770f5a60b44de22ee8fb8ed224efb58ed9fb50586c8d6b78161811cf",
      "hash": "0x",
      "sorted_hashes": [
        "0x356f7b2034f7c789ac0118725047eed6aacf54af0e4385e653fa928596c1ccec",
        "0x608bbd5ba0e29a1506780c594e2de85e0a62e7ea8c9d7bdbd2e4a6cced40b5ce",
        "0x272cf01f0c371697319e95ffade01a221ed60a2fea530d1f252f0966b868157d",
        "0x8e32d7a9533edbb5fe0af56b58a081adf56fdcc084d7b870ee76099c57f056cc",
        "0x344c38025b6398676c1014205c69e6c391dd986f1a1e6c9337e7ac1b9daac2f7",
        "0x428df21c9bae763a91f93587847a596b8e3a77bcbe51c7f218fa3b33906279ec",
        "0x6cff4b5e8568c9d8b612c7dedefbad0553db5da9e9abb4b897a43e28fb43360d",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    },
    {
      "property": "0x010000000000000188c5386e0c2a5a5444aca7b06a37192d6a65b43687280111a0b898f158e7b5ad000000040000000000000000",
      "value": "0xe821d1b50945ff736992d0af793684dd53ac7fa7fc03d8fc2094952d153396f1904513850b4f76fcfeaef9c44dcb6d7de1921674",
      "salt": "0x40c8f60c7fe30c33dc5eb80a321a53ee28be31e95353dbb4dec1f05312c545d2",
      "hash": "0x",
      "sorted_hashes": [
        "0xaed39af10b7c79ce60732e67d1e6f4476c69fa1f71b30e066124c54ff7d164c1",
        "0x2b4be93fe7c4d4df58cb4410777e008ac4cfad2552b9189116b17c931439f955",
        "0xbdad8d05907da08861526d15a497be5ea51c919eaca696d9d4db58e78c073292",
        "0x7678db5975ce57c3a5460218deafb59e1d7d2bfc8b5c8345c78d1395060fe998",
        "0xc07430e27007ac41e71f4efa61fbc8141c4220bbe06ae570179aa403d144b1dd",
        "0x428df21c9bae763a91f93587847a596b8e3a77bcbe51c7f218fa3b33906279ec",
        "0x6cff4b5e8568c9d8b612c7dedefbad0553db5da9e9abb4b897a43e28fb43360d",
        "0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    }
  ]
}
`
	original, dr, err := ConvertJSONProofs(payload)
	assert.NoError(t, err)
	opt, err = OptimizeProofs(original,  dr, sha256.New())
	assert.NoError(t, err)
	assert.Len(t, opt, 12)
	assert.Len(t, opt[0].SortedHashes, 8)
	assert.Len(t, opt[1].SortedHashes, 1)
	assert.Len(t, opt[2].SortedHashes, 4)
	assert.Len(t, opt[3].SortedHashes, 2)
	assert.Len(t, opt[4].SortedHashes, 3)
	assert.Len(t, opt[5].SortedHashes, 1)
	assert.Len(t, opt[6].SortedHashes, 2)
	assert.Len(t, opt[7].SortedHashes, 6)
	assert.Len(t, opt[8].SortedHashes, 4)
	assert.Len(t, opt[9].SortedHashes, 1)
	assert.Len(t, opt[10].SortedHashes, 1)
	assert.Len(t, opt[11].SortedHashes, 3)
	optHashesCount := 0
	for i := 0; i < len(opt); i++ {
		optHashesCount += len(opt[i].SortedHashes)
		fmt.Printf("Hashes%d %x\n", i, opt[i].SortedHashes)
	}
	origHashesCount := 0
	for i := 0; i < len(original); i++ {
		origHashesCount += len(original[i].SortedHashes)
	}
	fmt.Printf("Original[%d] -> Optimized[%d] with factor[%f]\n", origHashesCount, optHashesCount, float64(optHashesCount)/float64(origHashesCount))
}
