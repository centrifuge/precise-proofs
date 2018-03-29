/*
Package preciseproofs lets you construct merkle trees out of protobuf messages and create proofs for fields of
an object by just specifying the dot notation of a field.

Field names are not taken from the struct attributes but the protobuf field names. Protobuf field names stay the same
across different programming languages (the struct field names are camel cased to follow Go's style guide which they
would not be in a javascript implementation.

Note: this is a basic implementation that lacks support for serializing more complex structs. The interfaces and
functions in this library will change significantly in the near future.
 */
package preciseproofs

//go:generate protoc -I $PROTOBUF/src/ -I. -I $GOPATH/src --go_out=$GOPATH/src/ proof.proto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/go-bongo/go-dotaccess"
	"github.com/golang/protobuf/proto"
	merkle "github.com/xsleonard/go-merkle"
	"golang.org/x/crypto/blake2b"
	"reflect"
	"sort"
	"strings"
	"encoding/base64"
	"strconv"
)

// NodeValueSeparator is used to separate Property, Value, Salt.
const NodeValueSeparator = ","

// DocumentTree is a helper object to create a MerkleTree and proofs for fields in the Document
type DocumentTree struct {
	PropertyList []string
	MerkleTree   merkle.Tree
	RootHash 		 []byte
	Salts        proto.Message
	Document     proto.Message
}

// NewDocumentTree returns an empty DocumentTree
func NewDocumentTree () DocumentTree {
	return DocumentTree{[]string{}, merkle.NewTree(), []byte{}, nil, nil}
}

// AddDocument fills a MerkleTree with a provided Document and Salts
func (doctree *DocumentTree) AddDocument(document, salts proto.Message) (err error){
	leaves, propertyList, err := FlattenMessage(document, salts)
	if err != nil {
		return err
	}
	blakeHash, _ := blake2b.New256([]byte{})
	doctree.MerkleTree.Generate(leaves, blakeHash)
	doctree.RootHash = doctree.MerkleTree.Root().Hash
	doctree.PropertyList = propertyList
	doctree.Document = document
	doctree.Salts = salts
	return nil
}

// IsEmpty returns false if the tree contains no leaves
func (doctree *DocumentTree) IsEmpty () bool {
	return len(doctree.MerkleTree.Nodes) == 0
}

func (doctree *DocumentTree) CreateProof(prop string) (proof Proof, err error) {
	if doctree.IsEmpty() {
		return Proof{}, fmt.Errorf("Can't create proof for empty MerkleTree")
	}

	value, err := getStringValueByProperty(prop, doctree.Document)
	if err != nil {
		return Proof{}, err
	}
	salt, err := getByteValueByProperty(prop, doctree.Salts)

	leaf, err := getIndexOfString(doctree.PropertyList, prop)
	if err != nil {
		return Proof{}, err
	}

	hashes, err := doctree.pickHashesFromMerkleTree(uint64(leaf))
	if err != nil {
		return Proof{}, err
	}

	proof = Proof{Property: prop, Value: value, Salt: salt, Hashes: hashes}
	return
}

// pickHashesFromMerkleTree takes the required hashes needed to create a proof
func (doctree *DocumentTree) pickHashesFromMerkleTree(leaf uint64) (hashes []*MerkleHash, err error) {
	proofNodes, err := CalculateProofNodeList(leaf, uint64(len(doctree.MerkleTree.Leaves())))

	if err != nil {
		return hashes, err
	}

	hashes = make([]*MerkleHash, len(proofNodes))

	for i, n := range proofNodes {
		h := doctree.MerkleTree.Nodes[n.Leaf].Hash
		if n.Left {
			hashes[i] = &MerkleHash{h, nil}
		} else {
			hashes[i] = &MerkleHash{nil, h}

		}
	}
	return hashes, nil
}

// ValidateProof by comparing it to the tree's RootHash
func (doctree *DocumentTree) ValidateProof(proof *Proof) (valid bool, err error) {
	return ValidateProof(proof, doctree.RootHash)
}

func ValidateProof(proof *Proof, rootHash []byte) (valid bool, err error) {
	hash, err := CalculateHashForProofField(proof)
	if err != nil {
		return false, err
	}

	valid, err = ValidateProofHashes(hash, proof.Hashes, rootHash)
	return
}

// ValueToString takes any supported interface and returns a string representation of the value. This is used calculate
// the hash and create the proof object.
func ValueToString(value interface{}) (s string, err error) {
	switch t := reflect.TypeOf(value).String(); t {
	case "string":
		return value.(string), nil
	case "int64":
		return strconv.FormatInt(value.(int64), 10), nil
	case "[]uint8":
		return base64.StdEncoding.EncodeToString(value.([]uint8)), nil
	default:
		return "", errors.New(fmt.Sprint("Got unsupported value:", t))
	}
	return
}

// LeafNode represents a field that can be hashed to create a merkle MerkleTree
type LeafNode struct {
	Property string
	Value    interface{}
	Salt     []byte
}

// ConcatValue concatenates property, value & salt into one byte slice using the NodeValueSeparator.
func ConcatValues(prop string, value interface{}, salt []byte) (payload []byte, err error) {
	propBytes := []byte(prop)
	valueString, err := ValueToString(value)
	if err != nil {
		return []byte{}, err
	}

	payload = append(payload, propBytes...)
	payload = append(payload, []byte(NodeValueSeparator)...)
	payload = append(payload, []byte(valueString)...)
	payload = append(payload, []byte(NodeValueSeparator)...)
	payload = append(payload, salt[:32]...)
	return
}

// ConcatNode concatenates a leaf node into a byte slice that is the input for the hash function.
func ConcatNode(n *LeafNode) (payload []byte, err error) {
	payload, err = ConcatValues(n.Property, n.Value, n.Salt)
	if err != nil {
		return []byte{}, err
	}
	return
}

// GenerateRandomSalt creates a 32 byte slice with random data using the crypto/rand RNG
func GenerateRandomSalt() (salt []byte) {
	randbytes := make([]byte, 32)
	rand.Read(randbytes)
	return randbytes
}

// FillSalts is a helper message that iterates over all fields in a proto.Message struct and fills them with 32 byte
// random values.
//
// This method will fail if there are any fields of type other than []byte (bytes in protobuf) in the
// message.
func FillSalts(message proto.Message) (err error) {
	v := reflect.ValueOf(message).Elem()

	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Type().String() != "[]uint8" {
			return fmt.Errorf("Invalid type (%s) for field", f.Type().String())
		}
		salt := GenerateRandomSalt()
		saltVal := reflect.ValueOf(salt)
		f.Set(saltVal)
	}

	return nil
}

// LeafList is a list implementation that can be sorted by the LeafNode.Property value. This is needed for ordering all
// leaves before generating a MerkleTree out of it.
type LeafList []LeafNode

// Len returns the length of the list
func (s LeafList) Len() int {
	return len(s)
}

// Swap two items in the list
func (s LeafList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less compares two strings lexicographically
func (s LeafList) Less(i, j int) bool {
	return strings.Compare(s[i].Property, s[j].Property) == -1
}

// getPropertyNameFromProtobufTag extracts the name attribute from the protobuf tag, the tag name is essential in defining
// the oder, not the struct field name.
func getPropertyNameFromProtobufTag(tag string) (name string, err error) {
	tagList := strings.Split(tag, ",")
	for _, v := range tagList {
		if strings.HasPrefix(v, "name") {
			return strings.Split(v, "=")[1], nil
		}
	}
	return "", fmt.Errorf("Invalid protobuf annotation: %s", tag)
}

// FlattenMessage takes a protobuf message Struct and flattens it into an array of nodes. This currently doesn't support
// nested structures and lists.
func FlattenMessage(message, messageSalts proto.Message) (nodes [][]byte, propOrder []string, err error) {
	leaves := LeafList{}
	v := reflect.ValueOf(message).Elem()
	t := v.Type()
	s := reflect.ValueOf(messageSalts).Elem()

	for i := 0; i < v.NumField(); i++ {
		value := v.Field(i).Interface()
		tag := v.Type().Field(i).Tag.Get("protobuf")
		prop, err := getPropertyNameFromProtobufTag(tag)
		if err != nil {
			return [][]byte{}, []string{}, err
		}
		salt := reflect.Indirect(s).FieldByName(t.Field(i).Name).Interface().([]byte)
		leaf := LeafNode{
			Property: prop,
			Value:    value,
			Salt:     salt,
		}
		leaves = append(leaves, leaf)
	}

	sort.Sort(leaves)
	nodes = make([][]byte, leaves.Len())
	propOrder = make([]string, leaves.Len())

	for i := 0; i < leaves.Len(); i++ {
		nodes[i], err = ConcatNode(&leaves[i])
		if err != nil {
			return nodes, propOrder, err
		}
		propOrder[i] = leaves[i].Property
	}

	return nodes, propOrder, err
}

// getStringValueByProperty gets a value from a (nested) struct and returns the value. This method does not yet
// support nested structs. It converts the value to a string representation.
func getStringValueByProperty(prop string, message proto.Message) (value string, err error) {
	v, err := dotaccess.Get(message, prop)
	if err != nil {
		return "", err
	}
	value, err = ValueToString(v)
	return
}

// getByteValueByProperty tries to use the dot notation to access a field. This is used specifically to get the salt
// value which is always a byte slice.
func getByteValueByProperty(prop string, message proto.Message) (value []byte, err error) {
	v, err := dotaccess.Get(message, prop)
	if err != nil {
		return []byte{}, err
	}
	return v.([]byte), nil
}

func getIndexOfString(slice []string, match string) (index int, err error) {
	for i, el := range slice {
		if el == match {
			return i, nil
		}
	}
	return index, fmt.Errorf("getIndexOfString: No match found")
}

// HashTwoValues concatenate two hashes to calculate hash out of the result. This is used in the MerkleTree calculation code
// as well as the validation code.
func HashTwoValues(a, b []byte) (hash []byte) {
	data := make([]byte, 64)
	copy(data[:32], a[:32])
	copy(data[32:], b[:32])
	h := blake2b.Sum256(data)
	hash = h[:]
	return
}

// po2 calculates 2 to the power of i
func po2(i uint64) (r uint64) {
	r = uint64(1)
	for l := i; l > 0; l-- {
		r = r * 2
	}
	return
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
	level := height - 1
	lastNodeInLevel := leafCount-1
	offset := uint64(0)
	nodes = make([]*HashNode, height-1)

	for i := level; i > 0; i-- {
		// only add hash if this isn't an odd end
		if !(node == lastNodeInLevel && (lastNodeInLevel+1) % 2 == 1) {
			if node % 2 == 0 {
				nodes[index] = &HashNode{false, offset+node+1}
			} else {
				nodes[index] = &HashNode{true, offset+node-1}
			}
			index++
		}
		node = node/2

		offset += lastNodeInLevel+1
		lastNodeInLevel = (lastNodeInLevel+1) / 2 + (lastNodeInLevel+1) % 2 - 1
		level--
	}
	return nodes[:index], nil
}

// CalculateHashForProofField takes a Proof struct and returns a hash of the concatenated property name, value & salt.
// Uses ConcatValues internally.
func CalculateHashForProofField(proof *Proof) (hash []byte, err error) {
	input, err := ConcatValues(proof.Property, proof.Value, proof.Salt)
	if err != nil {
		return []byte{}, err
	}

	h := blake2b.Sum256(input)
	hash = h[:]
	return hash, nil
}

// ValidateProofHashes calculates the merkle root based on a list of left/right hashes.
func ValidateProofHashes(hash []byte, hashes []*MerkleHash, rootHash []byte) (valid bool, err error) {
	for i := 0; i < len(hashes); i++ {
		if len(hashes[i].Left) == 0 {
			hash = HashTwoValues(hash, hashes[i].Right)
		} else {
			hash = HashTwoValues(hashes[i].Left, hash)
		}
	}

	if !bytes.Equal(hash, rootHash) {
		return false, errors.New("Hash does not match")
	}

	return true, nil
}
