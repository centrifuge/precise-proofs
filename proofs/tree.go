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


Note: this is a basic implementation that lacks support for serializing more complex structs. The interfaces and
functions in this library will change significantly in the near future.

Example Usage

		func main () {
			// ExampleDocument is a protobuf message
			document := documents.ExampleDocument{
				Value1: 1,
				ValueA: "Foo",
				ValueB: "Bar",
				ValueBytes1: []byte("foobar"),
			}

			// The FillSalts method is a helper function that fills all fields with 32
			// random bytes. SaltedExampleDocument is a protobuf message that has the
			// same structure as ExampleDocument but has all `bytes` field types.
			salts := documents.SaltedExampleDocument{}
			proofs.FillSalts(&salts)

			doctree := proofs.NewDocumentTree()
			ssha256Hash := sha256.New()
			doctree.SetHashFunc(sha256Hash)
			doctree.FillTree(&document, &salts)
			fmt.Printf("Generated tree: %s\n", doctree.String())

			proof, _ := doctree.CreateProof("ValueA")
			proofJson, _ := json.Marshal(proof)
			fmt.Println("Proof:\n", string(proofJson))

			valid, _ := doctree.ValidateProof(&proof)

			fmt.Printf("Proof validated: %v\n", valid)
		}

 */
package proofs

// Use below command to update proof protobuf file.
//go:generate protoc -I $PROTOBUF/src/ -I. -I $GOPATH/src --go_out=$GOPATH/src/ proof.proto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes"
	"github.com/go-bongo/go-dotaccess"
	"github.com/xsleonard/go-merkle"
)

// DocumentTree is a helper object to create a merkleTree and proofs for fields in the document
type DocumentTree struct {
	propertyList []string
	merkleTree   merkle.Tree
	rootHash     []byte
	salts        proto.Message
	document     proto.Message
	hash         hash.Hash
}

func (doctree *DocumentTree) String() string {
	return fmt.Sprintf(
		"DocumentTree with Hash [%s] and [%d] leaves",
		base64.StdEncoding.EncodeToString(doctree.RootHash()),
		len(doctree.merkleTree.Leaves()),
	)
}

// NewDocumentTree returns an empty DocumentTree
func NewDocumentTree() DocumentTree {
	return DocumentTree{[]string{}, merkle.NewTree(), []byte{}, nil, nil, nil}
}

// SetHashFunc to an implementation of hash.Hash of your choice
func (doctree *DocumentTree) SetHashFunc(h hash.Hash) {
	doctree.hash = h
}

// FillTree fills a merkleTree with a provided document and salts
func (doctree *DocumentTree) FillTree(document, salts proto.Message) (err error) {
	if doctree.hash == nil {
		return fmt.Errorf("DocumentTree.hash is not set")
	}

	leaves, propertyList, err := FlattenMessage(document, salts)
	if err != nil {
		return err
	}

	doctree.merkleTree.Generate(leaves, doctree.hash)
	doctree.rootHash = doctree.merkleTree.Root().Hash
	doctree.propertyList = propertyList
	doctree.document = document
	doctree.salts = salts
	return nil
}

// IsEmpty returns false if the tree contains no leaves
func (doctree *DocumentTree) IsEmpty() bool {
	return len(doctree.merkleTree.Nodes) == 0
}

func (doctree *DocumentTree) RootHash() []byte {
	return doctree.rootHash
}

func (doctree *DocumentTree) Document() proto.Message {
	return doctree.document
}

// CreateProof takes a property in dot notation and returns a Proof object for the given field
func (doctree *DocumentTree) CreateProof(prop string) (proof Proof, err error) {
	if doctree.IsEmpty() {
		return Proof{}, fmt.Errorf("Can't create proof for empty merkleTree")
	}

	value, err := getStringValueByProperty(prop, doctree.document)
	if err != nil {
		return Proof{}, err
	}
	salt, err := getByteValueByProperty(prop, doctree.salts)

	leaf, err := getIndexOfString(doctree.propertyList, prop)
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
	proofNodes, err := CalculateProofNodeList(leaf, uint64(len(doctree.merkleTree.Leaves())))

	if err != nil {
		return hashes, err
	}

	hashes = make([]*MerkleHash, len(proofNodes))

	for i, n := range proofNodes {
		h := doctree.merkleTree.Nodes[n.Leaf].Hash
		if n.Left {
			hashes[i] = &MerkleHash{h, nil}
		} else {
			hashes[i] = &MerkleHash{nil, h}

		}
	}
	return hashes, nil
}

// ValidateProof by comparing it to the tree's rootHash
func (doctree *DocumentTree) ValidateProof(proof *Proof) (valid bool, err error) {
	return ValidateProof(proof, doctree.rootHash, doctree.hash)
}

// ValidateProof by comparing it to a given merkle tree root
func ValidateProof(proof *Proof, rootHash []byte, hashFunc hash.Hash) (valid bool, err error) {
	hash, err := CalculateHashForProofField(proof, hashFunc)
	if err != nil {
		return false, err
	}

	valid, err = ValidateProofHashes(hash, proof.Hashes, rootHash, hashFunc)
	return
}

// ValueToString takes any supported interface and returns a string representation of the value. This is used calculate
// the hash and to create the proof object.
func ValueToString(value interface{}) (s string, err error) {
	// nil values should return an empty string
	if reflect.TypeOf(value) == reflect.TypeOf(nil) {
		return "", nil
	}

	// nil pointers should also return an empty string
	if reflect.TypeOf(value).Kind() == reflect.Ptr && reflect.ValueOf(value).IsNil() {
		return "", nil
	}

	// Dereference any pointers
	if reflect.TypeOf(value).Kind() == reflect.Ptr {
		elem := reflect.ValueOf(value).Elem()

		// Check if elem is a zero value, return empty string if it is.
		if elem == reflect.Zero(reflect.TypeOf(elem)) {
			return "", nil
		}
		value = elem.Interface()
	}

	switch t := reflect.TypeOf(value); t {
	case reflect.TypeOf(""):
		return value.(string), nil
	case reflect.TypeOf(int64(0)):
		return strconv.FormatInt(value.(int64), 10), nil
	case reflect.TypeOf([]uint8{}):
		return base64.StdEncoding.EncodeToString(value.([]uint8)), nil
	case reflect.TypeOf(timestamp.Timestamp{}):
		v := value.(timestamp.Timestamp)
		return ptypes.TimestampString(&v), nil
	default:
		return "", errors.New(fmt.Sprint("Got unsupported value: %s", t))
	}
	return
}

// LeafNode represents a field that can be hashed to create a merkle tree
type LeafNode struct {
	Property string
	Value    interface{}
	Salt     []byte
}

// ConcatValues concatenates property, value & salt into one byte slice.
func ConcatValues(prop string, value interface{}, salt []byte) (payload []byte, err error) {
	propBytes := []byte(prop)
	valueString, err := ValueToString(value)
	if err != nil {
		return []byte{}, err
	}

	payload = append(payload, propBytes...)
	payload = append(payload, []byte(valueString)...)
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

// NewSalt creates a 32 byte slice with random data using the crypto/rand RNG
func NewSalt() (salt []byte) {
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
		if f.Type() != reflect.TypeOf([]uint8{}) {
			return fmt.Errorf("Invalid type (%s) for field", f.Type().String())
		}
		salt := NewSalt()
		saltVal := reflect.ValueOf(salt)
		f.Set(saltVal)
	}

	return nil
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

// Less compares two strings lexicographically
func (s LeafList) Less(i, j int) bool {
	return strings.Compare(s[i].Property, s[j].Property) == -1
}

// getPropertyNameFromProtobufTag extracts the name attribute from the protobuf tag, the tag name is essential in defining
// the order, not the struct field name.
func getPropertyNameFromProtobufTag(tag string) (name string, err error) {
	tagList := strings.Split(tag, ",")
	for _, v := range tagList {
		if strings.HasPrefix(v, "name") {
			return strings.Split(v, "=")[1], nil
		}
	}
	return "", fmt.Errorf("Invalid protobuf annotation: %s", tag)
}

// FlattenMessage takes a protobuf message struct and flattens it into an array of nodes. This currently doesn't support
// nested structures and lists.
//
// The fields are sorted lexicographically by their protobuf field names. 
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

// HashTwoValues concatenate two hashes to calculate hash out of the result. This is used in the merkleTree calculation code
// as well as the validation code.
func HashTwoValues(a []byte, b []byte, hashFunc hash.Hash) (hash []byte) {
	data := make([]byte, 64)
	copy(data[:32], a[:32])
	copy(data[32:], b[:32])
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
	lastNodeInLevel := leafCount - 1
	offset := uint64(0)
	nodes = make([]*HashNode, height-1)

	for i := level; i > 0; i-- {
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
		level--
	}
	return nodes[:index], nil
}

// CalculateHashForProofField takes a Proof struct and returns a hash of the concatenated property name, value & salt.
// Uses ConcatValues internally.
func CalculateHashForProofField(proof *Proof, hashFunc hash.Hash) (hash []byte, err error) {
	input, err := ConcatValues(proof.Property, proof.Value, proof.Salt)
	if err != nil {
		return []byte{}, err
	}
	hash = hashBytes(hashFunc, input)
	return hash, nil
}

// ValidateProofHashes calculates the merkle root based on a list of left/right hashes.
func ValidateProofHashes(hash []byte, hashes []*MerkleHash, rootHash []byte, hashFunc hash.Hash) (valid bool, err error) {
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
