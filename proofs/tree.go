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

Advanced options

Fields can be excluded from the flattener by setting the custom protobuf option
`proofs.exclude_from_tree` found in `proofs/proto/proof.proto`.

	message Document {
		string value_a = 1;
		string value_b = 2 [
			(proofs.exclude_from_tree) = true
		];
	}
*/
package proofs

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

	"github.com/centrifuge/precise-proofs/proofs/proto"
	"github.com/go-bongo/go-dotaccess"
	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/iancoleman/strcase"
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
func (doctree *DocumentTree) CreateProof(prop string) (proof proofspb.Proof, err error) {
	if doctree.IsEmpty() {
		return proofspb.Proof{}, fmt.Errorf("Can't create proof for empty merkleTree")
	}

	value, err := getStringValueByProperty(prop, doctree.document)
	if err != nil {
		return proofspb.Proof{}, err
	}
	salt, err := getByteValueByProperty(prop, doctree.salts)

	leaf, err := getIndexOfString(doctree.propertyList, prop)
	if err != nil {
		return proofspb.Proof{}, err
	}

	hashes, err := doctree.pickHashesFromMerkleTree(uint64(leaf))
	if err != nil {
		return proofspb.Proof{}, err
	}

	proof = proofspb.Proof{Property: prop, Value: value, Salt: salt, Hashes: hashes}
	return
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

// ValidateProof by comparing it to the tree's rootHash
func (doctree *DocumentTree) ValidateProof(proof *proofspb.Proof) (valid bool, err error) {
	return ValidateProof(proof, doctree.rootHash, doctree.hash)
}

// ValidateProof by comparing it to a given merkle tree root
func ValidateProof(proof *proofspb.Proof, rootHash []byte, hashFunc hash.Hash) (valid bool, err error) {
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
		return "", errors.New(fmt.Sprintf("Got unsupported value: %t", t))
	}
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
	if len(salt) != 32 {
		return []byte{}, fmt.Errorf("%s: Salt has incorrect length: %d instead of 32", prop, len(salt))
	}
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
		// Ignore fields starting with XXX_, those are protobuf internals
		if strings.HasPrefix(v.Type().Field(i).Name, "XXX_") {
			continue
		}

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

// messageFlattener takes a proto.Message and flattens it to a list of ordered nodes.
type messageFlattener struct {
	message        proto.Message
	messageType    reflect.Type
	messageValue   reflect.Value
	excludedFields map[string]struct{}
	salts          proto.Message
	saltsValue     reflect.Value
	leaves         LeafList
	nodes          [][]byte
	propOrder      []string
}

// generateLeafFromFieldIndex adds the LeafNode to LeafList for a field by it's
// index in the Message struct.
func (f *messageFlattener) generateLeafFromFieldIndex(index int) (err error) {
	// Ignore fields starting with XXX_, those are protobuf internals
	if strings.HasPrefix(f.messageType.Field(index).Name, "XXX_") {
		return nil
	}

	tag := f.messageType.Field(index).Tag.Get("protobuf")
	value := f.messageValue.Field(index).Interface()
	prop, err := getPropertyNameFromProtobufTag(tag)
	if err != nil {
		return err
	}

	// Check if the field has an exclude_from_tree option
	if _, ok := f.excludedFields[prop]; ok {
		return
	}

	salt := reflect.Indirect(f.saltsValue).FieldByName(f.messageType.Field(index).Name).Interface().([]byte)
	leaf := LeafNode{
		Property: prop,
		Value:    value,
		Salt:     salt,
	}
	f.leaves = append(f.leaves, leaf)
	return nil
}

// sortLeaves by the property attribute and copies the properties and
// concatenated byte values into the nodes
func (f *messageFlattener) sortLeaves() (err error) {
	sort.Sort(f.leaves)
	f.nodes = make([][]byte, f.leaves.Len())
	f.propOrder = make([]string, f.leaves.Len())

	for i := 0; i < f.leaves.Len(); i++ {
		f.nodes[i], err = ConcatNode(&f.leaves[i])
		if err != nil {
			return err
		}
		f.propOrder[i] = f.leaves[i].Property
	}
	return nil
}

// parseExtensions iterates over the prototype descripter to find fields that
// should be excluded
func (f *messageFlattener) parseExtensions() (err error) {
	descriptorMessage, ok := f.message.(descriptor.Message)
	if !ok {
		return fmt.Errorf("message [%s] does not implement descriptor.Message", f.message)
	}
	_, messageDescriptor := descriptor.ForMessage(descriptorMessage)

	for i := range messageDescriptor.Field {
		fieldDescriptor := messageDescriptor.Field[i]
		fV := reflect.ValueOf(fieldDescriptor).Elem()
		fType := fV.Type()
		fieldName := *fieldDescriptor.Name
		for i := 0; i < fV.NumField(); i++ {
			field := fV.Field(i)
			if fType.Field(i).Name != "Options" {
				continue
			}
			if proto.HasExtension(field.Interface().(proto.Message), proofspb.E_ExcludeFromTree) {
				ext, err := proto.GetExtension(field.Interface().(proto.Message), proofspb.E_ExcludeFromTree)
				if err != nil {
					continue
				}
				b, _ := ext.(*bool)
				if *b {
					f.excludedFields[fieldName] = struct{}{}
				}
			}
		}
	}
	return nil
}

// NewMessageFlattener instantiates a flattener for the given document
func NewMessageFlattener(message, messageSalts proto.Message) *messageFlattener {
	f := messageFlattener{message: message, salts: messageSalts}
	f.leaves = LeafList{}
	f.messageValue = reflect.ValueOf(message).Elem()
	f.messageType = f.messageValue.Type()
	f.saltsValue = reflect.ValueOf(messageSalts).Elem()
	f.excludedFields = make(map[string]struct{})
	return &f
}

// FlattenMessage takes a protobuf message struct and flattens it into an array
// of nodes. This currently doesn't support nested structures and lists.
//
// The fields are sorted lexicographically by their protobuf field names.
func FlattenMessage(message, messageSalts proto.Message) (nodes [][]byte, propOrder []string, err error) {
	f := NewMessageFlattener(message, messageSalts)

	if err := f.parseExtensions(); err != nil {
		return [][]byte{}, []string{}, err
	}

	for i := 0; i < f.messageValue.NumField(); i++ {
		err := f.generateLeafFromFieldIndex(i)
		if err != nil {
			return [][]byte{}, []string{}, err
		}
	}

	err = f.sortLeaves()
	if err != nil {
		return [][]byte{}, []string{}, err
	}
	return f.nodes, f.propOrder, nil
}

// getStringValueByProperty gets a value from a struct and returns the value. This method does not yet
// support nested structs. It converts the value to a string representation.
func getStringValueByProperty(prop string, message proto.Message) (value string, err error) {
	prop = strcase.ToCamel(prop)
	v, err := dotaccess.Get(message, prop)
	if err != nil {
		return "", err
	}
	value, err = ValueToString(v)
	return
}

// getByteValueByProperty tries to use the dot notation to access a field. This
// is used specifically to get the salt value which is always a byte slice.
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
