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
	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/centrifuge/go-merkle"
	"regexp"
	"github.com/iancoleman/strcase"
	"github.com/oleiade/reflections"
)

type TreeOptions struct {
	EnableHashSorting bool
}

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
func NewDocumentTree(proofOpts TreeOptions) DocumentTree {
	opts := merkle.TreeOptions{}
	if proofOpts.EnableHashSorting {
		opts.EnableHashSorting = proofOpts.EnableHashSorting
	}
	return DocumentTree{[]string{}, merkle.NewTreeWithOpts(opts), []byte{}, nil, nil, nil}
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
	if err != nil {
		return proofspb.Proof{}, err
	}

	leaf, err := getIndexOfString(doctree.propertyList, prop)
	if err != nil {
		return proofspb.Proof{}, err
	}

	if doctree.merkleTree.Options.EnableHashSorting {
		sortedHashes, err := doctree.pickHashesFromMerkleTreeAsList(uint64(leaf))
		if err != nil {
			return proofspb.Proof{}, err
		}
		proof = proofspb.Proof{Property: prop, Value: value, Salt: salt, SortedHashes: sortedHashes}
	} else {
		hashes, err := doctree.pickHashesFromMerkleTree(uint64(leaf))
		if err != nil {
			return proofspb.Proof{}, err
		}
		proof = proofspb.Proof{Property: prop, Value: value, Salt: salt, Hashes: hashes}
	}

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
	fieldHash, err := CalculateHashForProofField(proof, doctree.hash)
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

func DereferencePointer(value interface{}) (interface{}) {
	// nil values should return an empty string
	if reflect.TypeOf(value) == reflect.TypeOf(nil) {
		return nil
	}

	// nil pointers should also return an empty string
	if reflect.TypeOf(value).Kind() == reflect.Ptr && reflect.ValueOf(value).IsNil() {
		return nil
	}

	// Dereference any pointers
	if reflect.TypeOf(value).Kind() == reflect.Ptr {
		elem := reflect.ValueOf(value).Elem()

		// Check if elem is a zero value, return empty string if it is.
		if elem == reflect.Zero(reflect.TypeOf(elem)) {
			return nil
		}
		return  elem.Interface()
	}

	return value
}

// ValueToString takes any supported interface and returns a string representation of the value. This is used calculate
// the hash and to create the proof object.
func ValueToString(value interface{}) (s string, err error) {
	val := DereferencePointer(value)
	if val == nil {
		return "", nil
	}
	value = val

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
	Value    string
	Salt     []byte
}

// ConcatValues concatenates property, value & salt into one byte slice.
func ConcatValues(prop string, value string, salt []byte) (payload []byte, err error) {
	propBytes := []byte(prop)
	payload = append(payload, propBytes...)
	payload = append(payload, []byte(value)...)
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
func FillSalts(dataMessage, saltsMessage proto.Message) (err error) {
	dataMessageValue := reflect.Indirect(reflect.ValueOf(dataMessage))
	saltsMessageValue := reflect.Indirect(reflect.ValueOf(saltsMessage))

	for i := 0; i < saltsMessageValue.NumField(); i++ {
		valueField := dataMessageValue.Field(i)
		saltsField := saltsMessageValue.Field(i)
		saltsType := reflect.TypeOf(saltsField.Interface())

		if saltsType.Kind() == reflect.Ptr {
			saltsType = saltsType.Elem()
		}

		if strings.HasPrefix(saltsMessageValue.Type().Field(i).Name, "XXX_") {
			continue
		}

		if saltsType == reflect.TypeOf([]uint8{}) {

			newSalt := NewSalt()
			saltVal := reflect.ValueOf(newSalt)
			saltsMessageValue.Field(i).Set(saltVal)

		} else if saltsType.Kind() == reflect.Slice {
			a := reflect.SliceOf(saltsType.Elem())
			newSlice := reflect.MakeSlice(a, valueField.Len(), valueField.Len())
			saltsField.Set(newSlice)
			//// Set first element of list as the length salt
			//newSalt := NewSalt()
			//saltVal := reflect.ValueOf(newSalt)
			//saltsMessageValue.Field(i).Index(0).Set(saltVal)

			for j := 0; j < valueField.Len(); j++ {
				dataFieldItem := dataMessageValue.Field(i).Index(j)
				saltsFieldItem := saltsMessageValue.Field(i).Index(j)
				saltsFieldItemType := reflect.TypeOf(saltsFieldItem.Interface())
				saltsFieldItem.Set(reflect.Indirect(reflect.New(saltsFieldItemType)))

				var checkType reflect.Type
				if reflect.TypeOf(saltsFieldItem.Interface()).Kind() == reflect.Ptr {
					checkType = reflect.TypeOf(saltsFieldItem.Interface()).Elem()
				} else {
					checkType = reflect.TypeOf(saltsFieldItem.Interface())
				}

				if checkType.Kind() == reflect.Struct {
					saltsFieldItem.Set(reflect.New(checkType))
					err = FillSalts(dataFieldItem.Interface().(proto.Message), saltsFieldItem.Interface().(proto.Message))
				} else {
					deRefSaltsFieldItem := reflect.Indirect(saltsFieldItem)
					if reflect.TypeOf(deRefSaltsFieldItem.Interface()) != reflect.TypeOf([]uint8{}) {
						return fmt.Errorf("Invalid type (%s) for field", reflect.TypeOf(deRefSaltsFieldItem.Interface()).String())
					}
					newSalt := NewSalt()
					saltVal := reflect.ValueOf(newSalt)
					saltsFieldItem.Set(saltVal)
				}
			}

		} else if saltsType.Kind() == reflect.Struct {
			saltsField.Set(reflect.New(saltsType))
			err = FillSalts(valueField.Interface().(proto.Message), saltsField.Interface().(proto.Message))
		} else {
			if saltsType != reflect.TypeOf([]uint8{}) {
				return fmt.Errorf("Invalid type (%s) for field", reflect.TypeOf(saltsField.Interface()).String())
			}
			newSalt := NewSalt()
			saltVal := reflect.ValueOf(newSalt)
			saltsField.Set(saltVal)
		}

	}

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

func (f *messageFlattener) generateLeavesFromParent(propPrefix string, fcurrent *messageFlattener) (err error) {

	if err := fcurrent.parseExtensions(); err != nil {
		return err
	}

	for i := 0; i < fcurrent.messageValue.NumField(); i++ {
		valueField := fcurrent.messageValue.Field(i)
		valueType := reflect.TypeOf(valueField.Interface())
		reflectValueFieldType := fcurrent.messageType.Field(i)

		if valueType.Kind() == reflect.Ptr {
			valueType = valueType.Elem()
		}

		// Ignore fields starting with XXX_, those are protobuf internals
		if strings.HasPrefix(reflectValueFieldType.Name, "XXX_") {
			return nil
		}

		tag := reflectValueFieldType.Tag.Get("protobuf")
		reflectValue := fcurrent.messageValue.Field(i)
		value := reflectValue.Interface()
		reflectSaltsValue := fcurrent.saltsValue.Field(i)
		salts := reflectSaltsValue.Interface()

		prop, err := getPropertyNameFromProtobufTag(tag)
		if err != nil {
			return err
		}

		// Check if the field has an exclude_from_tree option
		if _, ok := fcurrent.excludedFields[prop]; ok {
			return nil
		}

		value = DereferencePointer(value)
		salts = DereferencePointer(salts)

		if valueType.Kind() == reflect.Slice {
			s := reflect.ValueOf(value)
			ss := reflect.ValueOf(salts)

			if s.Type() == reflect.TypeOf([]uint8{}) { //Specific case where byte is internally represented as []uint8, but we want to treat it as a whole
				value = value.([]byte)
				salt := reflect.Indirect(fcurrent.saltsValue).FieldByName(reflectValueFieldType.Name).Interface().([]byte)
				valueString, err := ValueToString(value)
				if err != nil {
					return err
				}
				f.appendLeaf(prop, valueString, salt)
				continue
			}

			//if fcurrent.saltsValue.FieldByName(fcurrent.messageType.Field(i).Name).Len() <= s.Len() {
			//	return errors.New(fmt.Sprintf("Salts length provided does not match standard n+1 for field %s", fcurrent.messageType.Field(i).Name))
			//}

			//salt := fcurrent.saltsValue.FieldByName(fcurrent.messageType.Field(i).Name).Index(0).Interface().([]byte)
			//f.appendLeaf(fmt.Sprintf("%s%s.length", propPrefix, prop), strconv.Itoa(s.Len()), salt)
			for j := 0; j < s.Len(); j++ {
				sval := reflect.Indirect(s.Index(j))
				if reflect.TypeOf(sval.Interface()).Kind() == reflect.Struct {

					if reflect.TypeOf(s.Index(j).Interface()) == reflect.TypeOf(timestamp.Timestamp{}) { //Specific case where we support serialization for a non primitive complex struct
						valueString, err := ValueToString(s.Index(j).Interface())
						if err != nil {
							return err
						}
						//salt := fcurrent.saltsValue.FieldByName(fcurrent.messageType.Field(i).Name).Index(j+1).Interface().([]byte) // j+1 as we reserve salts[0] to length of slice
						salt := fcurrent.saltsValue.FieldByName(fcurrent.messageType.Field(i).Name).Index(j).Interface().([]byte) // j+1 as we reserve salts[0] to length of slice
						f.appendLeaf(fmt.Sprintf("%s%s", propPrefix, prop), valueString, salt)
					} else {
						propItem := fmt.Sprintf("%s%s[%d]", propPrefix, prop, j)
						saltsValue := ss.Index(j).Interface().(proto.Message)
						fchild := NewMessageFlattener(s.Index(j).Interface().(proto.Message), saltsValue)
						err = f.generateLeavesFromParent(fmt.Sprintf("%s%s.", propPrefix, propItem), fchild)
					}
				} else {
					propItem := fmt.Sprintf("%s%s[%d]", propPrefix, prop, j)
					conv, err := ConvertReflectValueToSupportedPrimitive(s.Index(j))
					if err != nil {
						return err
					}
					valueString, err := ValueToString(conv)
					if err != nil {
						return err
					}

					//salt := fcurrent.saltsValue.FieldByName(fcurrent.messageType.Field(i).Name).Index(j+1).Interface().([]byte) // j+1 as we reserve salts[0] to length of slice
					salt := fcurrent.saltsValue.FieldByName(fcurrent.messageType.Field(i).Name).Index(j).Interface().([]byte) // j+1 as we reserve salts[0] to length of slice
					f.appendLeaf(propItem, valueString, salt)
				}
			}

		} else if valueType.Kind() == reflect.Struct {
			if valueType == reflect.TypeOf(timestamp.Timestamp{}) { //Specific case where we support serialization for a non primitive complex struct
				valueString, err := ValueToString(value)
				if err != nil {
					return err
				}
				salt := fcurrent.saltsValue.FieldByName(reflectValueFieldType.Name).Interface().([]byte)
				f.appendLeaf(fmt.Sprintf("%s%s", propPrefix, prop), valueString, salt)
			} else {
				fchild := NewMessageFlattener(reflectValue.Interface().(proto.Message), reflectSaltsValue.Interface().(proto.Message))
				err = f.generateLeavesFromParent(fmt.Sprintf("%s%s.",propPrefix, prop), fchild)
			}
		} else {
			valueString, err := ValueToString(value)
			if err != nil {
				return err
			}
			salt := reflect.Indirect(fcurrent.saltsValue).FieldByName(reflectValueFieldType.Name).Interface().([]byte)
			f.appendLeaf(fmt.Sprintf("%s%s", propPrefix, prop), valueString, salt)
		}
	}

	return
}

func ConvertReflectValueToSupportedPrimitive(value reflect.Value) (converted interface{}, err error) {
	switch t := reflect.TypeOf(value.Interface()); t {
	case reflect.TypeOf(""):
		converted = value.Interface().(string)
	case reflect.TypeOf(int64(0)):
		converted = value.Interface().(int64)
	case reflect.TypeOf([]uint8{}):
		converted = value.Interface().([]uint8)
	case reflect.TypeOf(timestamp.Timestamp{}):
		converted = value.Interface().(timestamp.Timestamp)
	default:
		return "", errors.New(fmt.Sprintf("Got unsupported value: %t", t))
	}
	return
}

func (f *messageFlattener) appendLeaf(prop string, value string, salt[]byte) {
	leaf := LeafNode{
		Property: prop,
		Value:    value,
		Salt:     salt,
	}
	f.leaves = append(f.leaves, leaf)
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
	f.messageValue = reflect.Indirect(reflect.ValueOf(message))
	f.messageType = f.messageValue.Type()
	f.saltsValue = reflect.Indirect(reflect.ValueOf(messageSalts))
	f.excludedFields = make(map[string]struct{})
	return &f
}

// FlattenMessage takes a protobuf message struct and flattens it into an array
// of nodes. This currently doesn't support nested structures and lists.
//
// The fields are sorted lexicographically by their protobuf field names.
func FlattenMessage(message, messageSalts proto.Message) (nodes [][]byte, propOrder []string, err error) {
	f := NewMessageFlattener(message, messageSalts)

	err = f.generateLeavesFromParent("", f)
	if err != nil {
		return
	}

	err = f.sortLeaves()
	if err != nil {
		return [][]byte{}, []string{}, err
	}
	return f.nodes, f.propOrder, nil
}

// normalizeDottedProperty performs camel case conversion without removing slice characters ([])
func normalizeDottedProperty(prop string) (string) {
	arr := strings.Split(prop, ".")
	for idx, key := range arr {
		var propAux string
		re := regexp.MustCompile(`(.*)(\[(.*)])`)
		if re.MatchString(key) {
			prefix := re.ReplaceAllString(key, "$1")
			strIdx := re.ReplaceAllString(key, "$3")
			propAux = fmt.Sprintf("%s[%s]", strcase.ToCamel(prefix), strIdx)
		} else {
			propAux = strcase.ToCamel(key)
		}

		if idx == 0 {
			prop = fmt.Sprintf("%s", propAux)
		} else {
			prop = fmt.Sprintf("%s.%s", prop, propAux)
		}
	}
	return prop
}

// getDottedValueByProperty takes a dotted property and retrieves the interface value of an object
// It supports nested fields and slices
func getDottedValueByProperty(prop string, value interface{}) (interface{}, error) {
	prop = normalizeDottedProperty(prop)
	if reflect.TypeOf(value).Kind() != reflect.Struct && reflect.TypeOf(value).Kind() != reflect.Ptr {
		return nil, errors.New("non-struct interface not supported")
	}
	arr := strings.Split(prop, ".")
	value = DereferencePointer(value)
	var err error
	for _, key := range arr {
		re := regexp.MustCompile(`(.*)(\[(.*)])`)
		if re.MatchString(key) {
			prefix := re.ReplaceAllString(key, "$1")
			strIdx := re.ReplaceAllString(key, "$3")
			idx, err := strconv.Atoi(strIdx)
			if err != nil {
				return nil, err
			}
			value, err = reflections.GetField(value, prefix)
			if err != nil {
				return nil, err
			}
			if value == nil {
				return nil, nil
			}
			if reflect.ValueOf(value).Len() <= idx {
				return nil, errors.New("Index out of bounds for slice element")
			}
			value = reflect.ValueOf(value).Index(idx).Interface()
		} else {
			value, err = reflections.GetField(value, key)
			if err != nil {
				return nil, err
			}
			if value == nil {
				return nil, nil
			}
		}

	}

	return value, nil
}

// getStringValueByProperty returns the value of a struct. It converts the value to a string representation.
func getStringValueByProperty(prop string, message proto.Message) (value string, err error) {
	var valueInterface interface{}
	valueInterface, err = getDottedValueByProperty(prop, message)
	if err != nil {
		return
	}
	value, err = ValueToString(valueInterface)
	return
}

func getByteValueByProperty(prop string, message proto.Message) (value []byte, err error) {
	val, err := getStringValueByProperty(prop, message)
	if err != nil {
		return value, err
	}

	value, err = base64.StdEncoding.DecodeString(val)
	return value, err
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
