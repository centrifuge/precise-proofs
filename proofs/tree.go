/*
Package proofs lets you construct merkle trees out of protobuf messages and create proofs for fields of
an object by just specifying the dot notation of a field.

Field names are not taken from the struct attributes but the protobuf field names. Protobuf field names stay the same
across different programming languages (the struct field names are camel cased to follow Go's style guide which they
would not be in a javascript implementation.

Supported types:
* string
* int64
* timestamp.Timestamp


Available Protobuf Options

Fields can be excluded from the flattener by setting the custom protobuf option
`proofs.exclude_from_tree` found in `proofs/proto/proof.proto`.

Fields can be treated as raw (already hashed values) by setting the option `proofs.hashed_field`.

	message Document {
		string value_a = 1;
		string value_b = 2 [
			(proofs.exclude_from_tree) = true
		];
		bytes value_c = 3 [
			(proofs.hashed_field) = true
		];
	}

Nested, Repeated and Mapped Structures

Nested, repeated, and map fields will be flattened following a dotted notation. Given the following example:

	message NestedDocument {
	  string fieldA = 1;
	  repeated Document fieldB = 2;
	  repeated string fieldC = 3;
	  map<string, Document> fieldD = 4 [
	      (proofs.key_length) = 4
	  ];
	  map<uint64, string> fieldE = 5;
	}

	message Document {
	  string fieldA = 1;
	}

	NestedDocument{
		fieldA: "foobar",
		fieldB: []Document{Document{fieldA: "1"}, Document{fieldA: "2"}},
		fieldC: []string{"a", "b", "c"},
		fieldD: map[string]Document{
		    "a": Document{fieldA: "1"},
		    "b": Document{fieldA: "2"},
		    "c": Document{fieldA: "3"},
		},
		fieldE: map[uint64]string{
		    0: "zero",
		    1: "one",
		    2: "two",
		},
	}

A tree will be created out of this document by flattening all the fields values
as leaves. This would result in a tree with the following leaves:

    - "fieldA" aka [1]
    - "fieldB.length" aka [2]
    - "fieldB[0]" aka [2, 0]
    - "fieldB[1]" aka [2, 1]
    - "fieldC.length" aka [3]
    - "fieldC[0]" aka [3, 0]
    - "fieldC[1]" aka [3, 1]
    - "fieldC[2]" aka [3, 2]
    - "fieldD.length" aka [4]
    - "fieldD[a]" aka [4, 97]
    - "fieldD[b]" aka [4, 98]
    - "fieldD[c]" aka [4, 99]
    - "fieldE.length" aka [5]
    - "fieldE[0]" aka [5, 0]
    - "fieldE[1]" aka [5, 1]
    - "fieldE[2]" aka [5, 2]

Proof format

This library defines a proof format that ensures both human readable, concise and secure Merkle proofs:

 {
    "readableName":"ValueA",
    "value":"Example",
    "salt":"1VWQFUGCXl1AYS0iAULHQow4XEjgJF/TpAuOO2Rnm+E=",
    "hashes":[
        { "right":"kYXAGhDdPiFMq1ZQMOZiKmSf1S1eHNgJ6BIPSIExOj8=" },
        { "left":"GDgT7Km6NK6k4N/Id4CZXErL3p6clNX7sVnlNyegdG0=" },
        { "right":"qOZzS+YM8t1OfC87zEKgkKz6q0f3wwk5+ed+PR/2cDA=" }
    ]
 }

This library can also create proofs with more compact property fields:

 {
    "compactName":[0,0,0,1],
    "value":"Example",
    "salt":"1VWQFUGCXl1AYS0iAULHQow4XEjgJF/TpAuOO2Rnm+E=",
    "hashes":[
        { "right":"kYXAGhDdPiFMq1ZQMOZiKmSf1S1eHNgJ6BIPSIExOj8=" },
        { "left":"GDgT7Km6NK6k4N/Id4CZXErL3p6clNX7sVnlNyegdG0=" },
        { "right":"qOZzS+YM8t1OfC87zEKgkKz6q0f3wwk5+ed+PR/2cDA=" }
    ]
 }

Sorted Hashes

This implementation allows for more concise representation of proofs, saving
some space that is valuable for on-chain verifications. The hash function to
hash two leaves is modified in this case in the following way:

  HashTwoNodes(A, B):
    if A > B:
	   return Hash(B, A)
	else:
	    return Hash(A, B)

This makes it unncessary to give a left/right designation in the proof. The drawback
of using this way of hashing a tree is that you can't make statements about the position
of a leaf in the tree.

The respective JSON for the proof would be:

  {
    "property":"ValueA",
    "value":"Example",
    "salt":"1VWQFUGCXl1AYS0iAULHQow4XEjgJF/TpAuOO2Rnm+E=",
    "sortedHashes":[
        "kYXAGhDdPiFMq1ZQMOZiKmSf1S1eHNgJ6BIPSIExOj8=",
        "GDgT7Km6NK6k4N/Id4CZXErL3p6clNX7sVnlNyegdG0=",
        "qOZzS+YM8t1OfC87zEKgkKz6q0f3wwk5+ed+PR/2cDA="
    ]
  }

There are a few things to note:
    - When calculating the hash of the leaf, the dot notation of the property, the value and salt should be concatenated to produce the hash.
    - The default proof expects values of documents to be salted to prevent rainbow table lookups.
    - The value is included in the file as a string value not a native type.

Compact Salt Slice
When you do processing for a document, if you want to save the salts, you can provide
an empty instance of Salts by TreeOption Salts. After processing you can use this compact to salt mapping for
rebuilding of the doctree for the same document in the future. In this way you get same rootHash
in different proof generation sessions for the same document.

Salt field for slice/map length

We encode the length of a slice or map field in the tree as an additional leaf so a proof can
be created about the size of a field. Default is "length". The new added length field can be customized
with the SaltsLengthSuffix option.

	message Document {
	  repeated string fieldA = 1;
	  map<string,string> fieldB = 2;
	}

Custom Document Prefix

Library supports adding a prefix to the document path by setting up `TreeOption.ParentPrefix` to the desired value.


*/
package proofs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"strings"

	"github.com/centrifuge/precise-proofs/proofs/proto"
	"github.com/golang/protobuf/proto"
	"github.com/xsleonard/go-merkle"
)

// DefaultSaltsLengthSuffix is the suffix used to store the length of slices (repeated) fields in the tree. It can be
// customized with the SaltsLenghtSuffix TreeOption
const DefaultSaltsLengthSuffix = "length"

type defaultValueEncoder struct{}

// EncodeToString encodes the bytes to string with 0x prefix
func (valueEncoder *defaultValueEncoder) EncodeToString(value []byte) string {
	return "0x" + hex.EncodeToString(value)
}

// ValueEncoder can be implemented by a type that can encode bytes to string
type ValueEncoder interface {
	EncodeToString([]byte) string
}

// TreeOptions allows customizing the generation of the tree
type TreeOptions struct {
	//	EnableHashSorting: Implement a merkle tree with sorted hashes
	EnableHashSorting bool
	GetSalt           GetSalt
	Salts             *Salts
	// SaltsLengthSuffix: As precise proofs support repeated fields, when generating the merkle tree we need to add a
	// leaf that represents the length of the slice. The default suffix is `Length`, although it is customizable so it
	// does not collide with potential field names of your own proto structs.
	SaltsLengthSuffix string
	Hash              hash.Hash
	ValueEncoder      ValueEncoder
	// ParentPrefix defines an arbitrary prefix to prepend to the parent, so all fields are prepended with it
	ParentPrefix      Property
	CompactProperties bool
}

type Salt struct {
	Compact []byte
	Value   []byte
}
type Salts []Salt
type GetSalt func(compact []byte) []byte

func defaultGetSalt(salts *Salts) func([]byte) []byte {
	return func(compact []byte) []byte {
		for ii := range *salts {
			if bytes.Compare((*salts)[ii].Compact, compact) == 0 {
				return (*salts)[ii].Value
			}
		}
		randbytes := make([]byte, 32)
		rand.Read(randbytes)
		*salts = append(*salts, Salt{Compact: compact, Value: randbytes})
		return randbytes
	}
}

// DocumentTree is a helper object to create a merkleTree and proofs for fields in the document
type DocumentTree struct {
	merkleTree merkle.Tree
	leaves     []LeafNode
	// Leaves can only be added if the tree is not filled yet. Once all leaves have been added, the root is
	// be generated by (`DocumentTree.Generate`) and this bool is set to true.
	filled            bool
	rootHash          []byte
	document          proto.Message
	getSalt           GetSalt
	salts             *Salts
	propertyList      []Property
	hash              hash.Hash
	saltsLengthSuffix string
	valueEncoder      ValueEncoder
	parentPrefix      Property
	compactProperties bool
}

func (doctree *DocumentTree) String() string {
	if doctree.valueEncoder == nil {
		return fmt.Sprintf("DocumentTree with Hash [%x] and [%d] leaves", doctree.RootHash(), len(doctree.merkleTree.Leaves()))
	}
	return fmt.Sprintf("DocumentTree with Hash [%s] and [%d] leaves", doctree.valueEncoder.EncodeToString(doctree.RootHash()), len(doctree.merkleTree.Leaves()))
}

// NewDocumentTree returns an empty DocumentTree
func NewDocumentTree(proofOpts TreeOptions) DocumentTree {
	opts := merkle.TreeOptions{
		DisableHashLeaves: true,
	}
	if proofOpts.EnableHashSorting {
		opts.EnableHashSorting = proofOpts.EnableHashSorting
	}
	var getSalt GetSalt
	if proofOpts.GetSalt != nil {
		getSalt = proofOpts.GetSalt
	}
	salts := &Salts{}
	if proofOpts.Salts != nil {
		salts = proofOpts.Salts
	}
	saltsLengthSuffix := DefaultSaltsLengthSuffix
	if proofOpts.SaltsLengthSuffix != "" {
		saltsLengthSuffix = proofOpts.SaltsLengthSuffix
	}
	var valueEncoder ValueEncoder = new(defaultValueEncoder)
	if proofOpts.ValueEncoder != nil {
		valueEncoder = proofOpts.ValueEncoder
	}
	return DocumentTree{
		propertyList:      []Property{},
		merkleTree:        merkle.NewTreeWithOpts(opts),
		getSalt:           getSalt,
		salts:             salts,
		saltsLengthSuffix: saltsLengthSuffix,
		leaves:            []LeafNode{},
		hash:              proofOpts.Hash,
		valueEncoder:      valueEncoder,
		parentPrefix:      proofOpts.ParentPrefix,
		compactProperties: proofOpts.CompactProperties,
	}
}

// AddLeaves appends list of leaves to the tree's leaves.
// This function can be called multiple times and leaves will be added from left to right. Note that the lexicographic
// sorting doesn't get applied in this method but in the protobuf flattening. The order in which leaves are added in
// in this method determine layout of the tree.
func (doctree *DocumentTree) AddLeaves(leaves []LeafNode) error {
	if doctree.filled {
		return errors.New("tree already filled")
	}
	doctree.leaves = append(doctree.leaves, leaves...)
	return nil
}

// AddLeaf appends a single leaf to the tree
// This function can be called multiple times and leaves will be added from left to right. Note that the lexicographic
// sorting doesn't get applied in this method but in the protobuf flattening. The order in which leaves are added in
// in this method determine layout of the tree.
func (doctree *DocumentTree) AddLeaf(leaf LeafNode) error {
	if doctree.filled {
		return errors.New("tree already filled")
	}
	doctree.leaves = append(doctree.leaves, leaf)
	return nil
}

// AddLeavesFromDocument iterates over a protobuf message, flattens it and adds all leaves to the tree
func (doctree *DocumentTree) AddLeavesFromDocument(document proto.Message) (err error) {
	if doctree.hash == nil {
		return fmt.Errorf("hash is not set")
	}
	var getSalt GetSalt
	if doctree.getSalt != nil {
		getSalt = doctree.getSalt
	} else {
		getSalt = defaultGetSalt(doctree.salts)
	}
	leaves, err := FlattenMessage(document, getSalt, doctree.saltsLengthSuffix, doctree.hash, doctree.valueEncoder, doctree.compactProperties, doctree.parentPrefix)
	if err != nil {
		return err
	}
	return doctree.AddLeaves(leaves)
}

// Generate calculated the merkle root with all supplied leaves. This method can only be called once and makes
// the tree immutable.
func (doctree *DocumentTree) Generate() error {
	if doctree.filled {
		return errors.New("tree already filled")
	}

	hashes := make([][]byte, len(doctree.leaves))
	for i, leaf := range doctree.leaves {
		if len(leaf.Hash) < 1 || leaf.Hashed {
			err := leaf.HashNode(doctree.hash, doctree.compactProperties)
			if err != nil {
				return err
			}
		}

		hashes[i] = leaf.Hash
	}
	err := doctree.merkleTree.Generate(hashes, doctree.hash)
	if err != nil {
		return fmt.Errorf("failed to generate merkle tree: %s", err)
	}

	doctree.rootHash = doctree.merkleTree.Root().Hash
	doctree.filled = true
	return nil
}

// GetLeafByProperty returns a leaf if it is found
func (doctree *DocumentTree) GetLeafByProperty(prop string) (int, *LeafNode) {
	for index, leaf := range doctree.leaves {
		if leaf.Property.ReadableName() == prop {
			return index, &leaf
		}
	}
	return 0, nil
}

// GetLeafByCompactProperty returns a leaf if it is found
func (doctree *DocumentTree) GetLeafByCompactProperty(prop []FieldNum) (int, *LeafNode) {
	for index, leaf := range doctree.leaves {
		if reflect.DeepEqual(leaf.Property.CompactName(), prop) {
			return index, &leaf
		}
	}
	return 0, nil
}

// PropertyOrder returns an with all properties of a doctree in order
func (doctree *DocumentTree) PropertyOrder() []Property {
	propOrder := []Property{}
	for _, leaf := range doctree.leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	return propOrder
}

// IsEmpty returns false if the tree contains no leaves
func (doctree *DocumentTree) IsEmpty() bool {
	return len(doctree.merkleTree.Nodes) == 0
}

func (doctree *DocumentTree) RootHash() []byte {
	return doctree.rootHash
}

// CreateProof takes a property in dot notation and returns a Proof object for the given field
func (doctree *DocumentTree) CreateProof(prop string) (proof proofspb.Proof, err error) {
	if doctree.IsEmpty() || !doctree.filled {
		err = fmt.Errorf("Can't create proof before generating merkle root")
		return
	}

	index, leaf := doctree.GetLeafByProperty(prop)
	if leaf == nil {
		return proofspb.Proof{}, fmt.Errorf("No such field: %s in obj", prop)
	}
	propName := leaf.Property.Name(doctree.compactProperties)
	proof = proofspb.Proof{
		Property: propName,
		Value:    leaf.Value,
		Salt:     leaf.Salt,
	}

	if leaf.Hashed {
		proof.Hash = leaf.Hash
	}

	if doctree.merkleTree.Options.EnableHashSorting {
		sortedHashes, err := doctree.pickHashesFromMerkleTreeAsList(uint64(index))
		if err != nil {
			return proofspb.Proof{}, err
		}
		proof.SortedHashes = sortedHashes
	} else {
		hashes, err := doctree.pickHashesFromMerkleTree(uint64(index))
		if err != nil {
			return proofspb.Proof{}, err
		}
		proof.Hashes = hashes
	}
	return proof, nil
}

// pickHashesFromMerkleTree takes the required hashes needed to create a proof
func (doctree *DocumentTree) pickHashesFromMerkleTree(leaf uint64) (hashes []*proofspb.MerkleHash, err error) {
	proofNodes, err := CalculateProofNodeList(leaf, uint64(len(doctree.merkleTree.Leaves())))
	if err != nil {
		return hashes, err
	}

	hashes = make([]*proofspb.MerkleHash, len(proofNodes))

	for i, n := range proofNodes {
		h := doctree.merkleTree.Nodes[n.Leaf].Hash
		if n.Left {
			hashes[i] = &proofspb.MerkleHash{Left: h, Right: nil}
		} else {
			hashes[i] = &proofspb.MerkleHash{Left: nil, Right: h}

		}
	}
	return hashes, nil
}

// pickHashesListFromMerkleTree takes the required hashes needed to create a proof as a list
func (doctree *DocumentTree) pickHashesFromMerkleTreeAsList(leaf uint64) (hashes [][]byte, err error) {
	proofNodes, err := CalculateProofNodeList(leaf, uint64(len(doctree.merkleTree.Leaves())))

	if err != nil {
		return hashes, err
	}

	hashes = make([][]byte, len(proofNodes))
	for i, n := range proofNodes {
		hashes[i] = doctree.merkleTree.Nodes[n.Leaf].Hash
	}
	return
}

// ValidateProof by comparing it to the tree's rootHash
func (doctree *DocumentTree) ValidateProof(proof *proofspb.Proof) (valid bool, err error) {
	var fieldHash []byte
	if len(proof.Hash) == 0 {
		fieldHash, err = CalculateHashForProofField(proof, doctree.hash)
	} else {
		fieldHash = proof.Hash
	}
	if err != nil {
		return false, err
	}
	if doctree.merkleTree.Options.EnableHashSorting {
		valid, err = ValidateProofSortedHashes(fieldHash, proof.SortedHashes, doctree.rootHash, doctree.hash)
	} else {
		valid, err = ValidateProofHashes(fieldHash, proof.Hashes, doctree.rootHash, doctree.hash)
	}
	return
}

// LeafNode represents a field that can be hashed to create a merkle tree
type LeafNode struct {
	Property Property
	Value    string
	Salt     []byte
	// Hash contains either the hash that is calculated from Value, Salt & Property or a user defined hash
	Hash []byte
	// If set to true, the the value added to the tree is LeafNode.Hash instead of the hash calculated from Value, Salt
	// & Property
	Hashed bool
}

// HashNode calculates the hash of a node provided it isn't already calculated.
func (n *LeafNode) HashNode(h hash.Hash, compact bool) error {
	if len(n.Hash) > 0 || n.Hashed {
		return nil
	}

	payload, err := ConcatValues(n.Property.Name(compact), n.Value, n.Salt)
	if err != nil {
		return err
	}

	defer h.Reset()
	_, err = h.Write(payload)
	if err != nil {
		return err
	}
	n.Hash = h.Sum(nil)
	return nil
}

// ConcatValues concatenates property, value & salt into one byte slice.
func ConcatValues(propName proofspb.PropertyName, value string, salt []byte) (payload []byte, err error) {
	payload = append(payload, AsBytes(propName)...)
	payload = append(payload, []byte(value)...)
	if len(salt) != 32 {
		return []byte{}, fmt.Errorf("%s: Salt has incorrect length: %d instead of 32", propName, len(salt))
	}
	payload = append(payload, salt[:32]...)
	return
}

// LeafList is a list implementation that can be sorted by the LeafNode.Property value. This is needed for ordering all
// leaves before generating a merkleTree out of it.
type LeafList []LeafNode

// Len returns the length of the list
func (s LeafList) Len() int {
	return len(s)
}

// Swap two items in the list
func (s LeafList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

type sortByReadableName struct{ LeafList }

// Compare by property name lexicographically
func (m sortByReadableName) Less(i, j int) bool {
	return strings.Compare(string(m.LeafList[i].Property.ReadableName()), string(m.LeafList[j].Property.ReadableName())) == -1
}

type sortByCompactName struct{ LeafList }

// Compare by property compact name
func (m sortByCompactName) Less(i, j int) bool {
	return bytes.Compare(AsBytes(m.LeafList[i].Property.Name(true)), AsBytes(m.LeafList[j].Property.Name(true))) == -1
}

// HashTwoValues concatenate two hashes to calculate hash out of the result. This is used in the merkleTree calculation code
// as well as the validation code.
func HashTwoValues(a []byte, b []byte, hashFunc hash.Hash) (hash []byte) {
	data := make([]byte, hashFunc.Size()*2)
	copy(data[:hashFunc.Size()], a[:hashFunc.Size()])
	copy(data[hashFunc.Size():], b[:hashFunc.Size()])
	return hashBytes(hashFunc, data)
}

// hashBytes takes a hash.Hash interface and hashes the provided value
func hashBytes(hashFunc hash.Hash, input []byte) []byte {
	defer hashFunc.Reset()
	_, err := hashFunc.Write(input[:])
	if err != nil {
		return []byte{}
	}
	return hashFunc.Sum(nil)
}

type HashNode struct {
	Left bool
	Leaf uint64
}

// CalculateProofNodeList returns a list of slice positions to fetch the nodes required for creating a proof from
// Tree.Nodes.
func CalculateProofNodeList(node, leafCount uint64) (nodes []*HashNode, err error) {
	if node >= leafCount {
		return nodes, errors.New("node index is too big for node count")
	}

	height, _ := merkle.CalculateHeightAndNodeCount(leafCount)
	index := 0
	lastNodeInLevel := leafCount - 1
	offset := uint64(0)
	nodes = make([]*HashNode, height-1)

	for level := height - 1; level > 0; level-- {
		// only add hash if this isn't an odd end
		if !(node == lastNodeInLevel && (lastNodeInLevel+1)%2 == 1) {
			if node%2 == 0 {
				nodes[index] = &HashNode{false, offset + node + 1}
			} else {
				nodes[index] = &HashNode{true, offset + node - 1}
			}
			index++
		}
		node = node / 2
		offset += lastNodeInLevel + 1
		lastNodeInLevel = (lastNodeInLevel+1)/2 + (lastNodeInLevel+1)%2 - 1
	}
	return nodes[:index], nil
}

// CalculateHashForProofField takes a Proof struct and returns a hash of the concatenated property name, value & salt.
// Uses ConcatValues internally.
func CalculateHashForProofField(proof *proofspb.Proof, hashFunc hash.Hash) (hash []byte, err error) {
	input, err := ConcatValues(proof.Property, proof.Value, proof.Salt)
	if err != nil {
		return []byte{}, err
	}
	hash = hashBytes(hashFunc, input)
	return hash, nil
}

// ValidateProofHashes calculates the merkle root based on a list of left/right hashes.
func ValidateProofHashes(hash []byte, hashes []*proofspb.MerkleHash, rootHash []byte, hashFunc hash.Hash) (valid bool, err error) {
	for i := 0; i < len(hashes); i++ {
		if len(hashes[i].Left) == 0 {
			hash = HashTwoValues(hash, hashes[i].Right, hashFunc)
		} else {
			hash = HashTwoValues(hashes[i].Left, hash, hashFunc)
		}
	}

	if !bytes.Equal(hash, rootHash) {
		return false, errors.New("Hash does not match")
	}

	return true, nil
}

// ValidateProofHashes calculates the merkle root based on a list of left/right hashes.
func ValidateProofSortedHashes(hash []byte, hashes [][]byte, rootHash []byte, hashFunc hash.Hash) (valid bool, err error) {
	for i := 0; i < len(hashes); i++ {
		if bytes.Compare(hash, hashes[i]) > 0 {
			hash = HashTwoValues(hashes[i], hash, hashFunc)
		} else {
			hash = HashTwoValues(hash, hashes[i], hashFunc)
		}
	}

	if !bytes.Equal(hash, rootHash) {
		return false, errors.New("Hash does not match")
	}

	return true, nil
}
