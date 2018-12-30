package proofs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/centrifuge/precise-proofs/proofs/proto"
)

// Property uniquely identifies a LeafNode
type Property struct {
	Parent     *Property
	Text       string
	Nums       []FieldNum
	NameFormat string
}

// NewProperty return a new root property
func NewProperty(name string, nums ...FieldNum) Property {
	return Property{
		Text: name,
		Nums: nums,
	}
}

// FieldNum is a compact, unique identifier for a Property, relative to its parent
type FieldNum = uint64

// SubFieldFormat represents how the property name of a struct field is derived from its parent
const SubFieldFormat = "%s.%s"

// ElemFormat represents how the property name of a slice or map element is derived from its parent
const ElemFormat = "%s[%s]"

// Name returns either the compact or human-reable name of a Property
func (n Property) Name(compact bool) proofspb.PropertyName {
	if compact {
		return &proofspb.Proof_CompactName{
			CompactName: &proofspb.FieldNums{
				Components: n.CompactName(),
			},
		}
	}
	return &proofspb.Proof_ReadableName{
		ReadableName: n.ReadableName(),
	}
}

// ReadableName returns the human-readable name of a property
func (n Property) ReadableName() string {
	if n.Parent == nil {
		return n.Text
	}
	return fmt.Sprintf(n.NameFormat, n.Parent.ReadableName(), n.Text)
}

// CompactName returns the compact name of a property, derived from protobuf tags
func (n Property) CompactName() (pn []FieldNum) {
	if n.Parent != nil {
		pn = append(pn, n.Parent.CompactName()...)
	}
	return append(pn, n.Nums...)
}

// FieldProp returns a child Property representing a field of a struct
func (n Property) FieldProp(name string, num FieldNum) (field Property) {
	field = NewProperty(name, num)
	field.Parent = &n
	field.NameFormat = SubFieldFormat
	return
}

// FieldPropFromTag takes the protobuf tag string of a struct field and returns a child Property representing that field of the struct
func (n Property) FieldPropFromTag(protobufTag string) (Property, error) {
	name, num, err := ExtractFieldTags(protobufTag)
	if err != nil {
		return Property{}, errors.Wrap(err, "failed to extract protobuf info from tags")
	}
	return n.FieldProp(name, num), nil
}

// SliceElemProp takes a repeated field index and returns a child Property representing that element of the repeated field
func (n Property) SliceElemProp(i FieldNum) Property {
	return Property{
		Parent:     &n,
		Text:       fmt.Sprintf("%d", i),
		Nums:       []FieldNum{i},
		NameFormat: ElemFormat,
	}
}

// MapElemProp takes a map key and returns a child Property representing the value at that key in the map
func (n Property) MapElemProp(k interface{}, maxLength uint64) (Property, error) {
	readableKey, err := keyToReadable(k)
	if err != nil {
		return Property{}, fmt.Errorf("failed to convert key to readable name: %s", err)
	}
	if uint64(len(readableKey)) > maxLength {
		return Property{}, fmt.Errorf("%q exceeds maximum key length %d", readableKey, maxLength)
	}
	compactKeyBytes := bytes.Repeat([]byte{0}, int(maxLength-uint64(len(readableKey))))
	compactKeyBytes = append(compactKeyBytes, []byte(readableKey)...)

	compactKey := make([]FieldNum, len(compactKeyBytes)/binary.Size(FieldNum(0)))
	err = binary.Read(bytes.NewReader(compactKeyBytes), binary.BigEndian, compactKey)
	if err != nil {
		return Property{}, errors.Wrap(err, "failed to decode compact key from bytes")
	}
	return Property{
		Parent:     &n,
		Text:       readableKey,
		Nums:       compactKey,
		NameFormat: ElemFormat,
	}, nil
}

// LengthProp returns a child Property representing the length of a repeated field
func (n Property) LengthProp() Property {
	return Property{
		Parent:     &n,
		Text:       "length",
		NameFormat: SubFieldFormat,
	}
}

// ExtractFieldTags takes the protobuf tag string of a struct field and returns the field name and number
func ExtractFieldTags(protobufTag string) (string, FieldNum, error) {
	var err error

	tagList := strings.Split(protobufTag, ",")
	if len(tagList) < 4 {
		err = errors.New("not enough elements in protobuf tag list")
		return "", 0, err
	}

	// first element describes field encoding: bytes, varint, etc.
	// second element is the field ordinal number
	num, err := strconv.ParseUint(tagList[1], 10, 64)
	if err != nil {
		err = errors.Wrap(err, "error parsing ordinal tag")
		return "", 0, err
	}

	// third element describes optionality of the field
	// fourth element has protobuf field name: e.g. 'name=ThisField'
	name := strings.TrimPrefix(tagList[3], "name=")
	if name == tagList[3] {
		err = errors.Errorf("error parsing protobuf field name: %q does not begin with %q", tagList[3], "name=")
		return "", 0, err
	}

	// other fields exist, but aren't needed

	return name, num, nil
}

// ReadableName creates a PropertyName from a human-readable name
func ReadableName(prop string) *proofspb.Proof_ReadableName {
	return &proofspb.Proof_ReadableName{
		ReadableName: prop,
	}
}

// CompactName creates a PropertyName from a list of FieldNums
func CompactName(prop ...FieldNum) *proofspb.Proof_CompactName {
	return &proofspb.Proof_CompactName{
		CompactName: &proofspb.FieldNums{
			Components: prop,
		},
	}
}

// AsBytes encodes a PropertyName for hashing
//
// Human-readable property names are encoded using UTF-8
// Compact property names are encoded by using big-endian encoding on the individual components
func AsBytes(propName proofspb.PropertyName) []byte {
	switch pn := propName.(type) {
	case *proofspb.Proof_ReadableName:
		return []byte(pn.ReadableName)
	case *proofspb.Proof_CompactName:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, pn.CompactName.Components)
		return buf.Bytes()
	}
	return nil
}

func keyToReadable(key interface{}) (string, error) {

	// special compound cases
	switch k := key.(type) {
	case []byte:
		return "0x" + hex.EncodeToString(k), nil
	}

	switch k := reflect.ValueOf(key); k.Kind() {
	case reflect.String:
		escaper := regexp.MustCompile(`\\|\.|\[|\]`)
		return escaper.ReplaceAllStringFunc(k.String(), func(match string) string {
			switch match {
			case `\`:
				return `\\`
			case `.`:
				return `\.`
			case `[`:
				return `\[`
			case `]`:
				return `\]`
			}
			panic(fmt.Sprintf("unexpected match %q for regex %s", match, escaper))
		}), nil
	case reflect.Bool:
		return fmt.Sprintf("%t", k.Bool()), nil
	case reflect.Int8:
		fallthrough
	case reflect.Int16:
		fallthrough
	case reflect.Int32:
		fallthrough
	case reflect.Int64:
		fallthrough
	case reflect.Int:
		return fmt.Sprintf("%d", k.Int()), nil
	case reflect.Uint8:
		fallthrough
	case reflect.Uint16:
		fallthrough
	case reflect.Uint32:
		fallthrough
	case reflect.Uint64:
		fallthrough
	case reflect.Uint:
		return fmt.Sprintf("%d", k.Uint()), nil
	}

	return "", fmt.Errorf("unsupported key type: %T", key)
}
