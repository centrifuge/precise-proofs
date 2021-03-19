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

	proofspb "github.com/centrifuge/precise-proofs/proofs/proto"
	"github.com/pkg/errors"
)

// Property uniquely identifies a LeafNode
type Property struct {
	Parent     *Property
	Text       string
	Compact    []byte
	NameFormat string
}

// NewProperty return a new root property
func NewProperty(name string, bytes ...byte) Property {
	return Property{
		Text:    name,
		Compact: bytes,
	}
}

// FieldNum is a compact, unique identifier for a Property, relative to its parent
type FieldNum uint32
type FieldNumForSliceLength uint64

func encode(n FieldNum) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, n)
	return buf.Bytes()
}

var Empty = Property{}

// SubFieldFormat represents how the property name of a struct field is derived from its parent
const SubFieldFormat = "%s.%s"

// ElemFormat represents how the property name of a slice or map element is derived from its parent
const ElemFormat = "%s[%s]"

// Name returns either the compact or human-reable name of a Property
func (n Property) Name(compact bool) proofspb.PropertyName {
	if compact {
		return &proofspb.Proof_CompactName{
			CompactName: n.CompactName(),
		}
	}
	return &proofspb.Proof_ReadableName{
		ReadableName: n.ReadableName(),
	}
}

// ReadableName returns the human-readable name of a property
func (n Property) ReadableName() string {
	if n.Parent == nil || n.Parent.Text == "" {
		return n.Text
	}
	return fmt.Sprintf(n.NameFormat, n.Parent.ReadableName(), n.Text)
}

// CompactName returns the compact name of a property, derived from protobuf tags
func (n Property) CompactName() (pn []byte) {
	if n.Parent != nil {
		pn = append(pn, n.Parent.CompactName()...)
	}
	return append(pn, n.Compact...)
}

// FieldProp returns a child Property representing a field of a struct
func (n Property) FieldProp(name string, num FieldNum) (field Property) {
	return Property{
		Text:       name,
		Compact:    encode(num),
		Parent:     &n,
		NameFormat: SubFieldFormat,
	}
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
func (n Property) SliceElemProp(i FieldNumForSliceLength) Property {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, i)
	return Property{
		Parent:     &n,
		Text:       fmt.Sprintf("%d", i),
		Compact:    buf.Bytes(),
		NameFormat: ElemFormat,
	}
}

// MapElemProp takes a map key and returns a child Property representing the value at that key in the map
func (n Property) MapElemProp(k interface{}, keyLength uint64) (Property, error) {
	readableKey, compactKey, err := keyNames(k, keyLength)
	if err != nil {
		return Property{}, fmt.Errorf("failed to convert key to readable name: %s", err)
	}

	return Property{
		Parent:     &n,
		Text:       readableKey,
		Compact:    compactKey,
		NameFormat: ElemFormat,
	}, nil
}

// LengthProp returns a child Property representing the length of a repeated field
func (n Property) LengthProp(readablePropertyLengthSuffix string) Property {
	return Property{
		Parent:     &n,
		Text:       readablePropertyLengthSuffix,
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

	ni := 3
	if tagList[ni] == "packed" {
		ni++
	}

	if len(tagList) < ni+1 {
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
	name := strings.TrimPrefix(tagList[ni], "name=")
	if name == tagList[ni] {
		err = errors.Errorf("error parsing protobuf field name: %q does not begin with %q", tagList[3], "name=")
		return "", 0, err
	}

	// other fields exist, but aren't needed
	return name, FieldNum(num), nil
}

// ReadableName creates a PropertyName from a human-readable name
func ReadableName(prop string) *proofspb.Proof_ReadableName {
	return &proofspb.Proof_ReadableName{
		ReadableName: prop,
	}
}

// CompactName creates a PropertyName from a byte slice
func CompactName(prop ...byte) *proofspb.Proof_CompactName {
	return &proofspb.Proof_CompactName{
		CompactName: prop,
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
		return pn.CompactName
	}
	return nil
}

func padTo(bs []byte, totalLength uint64) ([]byte, error) {
	if uint64(len(bs)) > totalLength {
		return nil, fmt.Errorf("given []byte longer than %d", totalLength)
	}
	padding := bytes.Repeat([]byte{0}, int(totalLength-uint64(len(bs))))
	return append(padding, bs...), nil
}

// returns the readable and compact names of the given map key
func keyNames(key interface{}, keyLength uint64) (string, []byte, error) {
	// special compound cases
	switch k := key.(type) {
	case []byte:
		readableKey := "0x" + hex.EncodeToString(k)
		compactKeyBytes, err := padTo(k, keyLength)
		if err != nil {
			return "", nil, errors.Wrapf(err, "failed to pad %q", readableKey)
		}
		return readableKey, compactKeyBytes, nil
	}

	switch k := reflect.ValueOf(key); k.Kind() {
	case reflect.Array:
		// if we receive an array, covert to a slice, and handle it like a slice
		sk := reflect.MakeSlice(reflect.SliceOf(k.Type().Elem()), k.Len(), k.Len())
		reflect.Copy(sk, k)
		return keyNames(sk.Interface(), keyLength)
	case reflect.String:
		escaper := regexp.MustCompile(`[\\.\[\]]`)
		readableKey := escaper.ReplaceAllStringFunc(k.String(), func(match string) string {
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
		})
		compactKeyBytes, err := padTo([]byte(readableKey), keyLength)
		if err != nil {
			return "", nil, errors.Wrapf(err, "failed to pad %q", readableKey)
		}
		return readableKey, compactKeyBytes, nil

		// simple bool case: single byte 0 or 1
	case reflect.Bool:
		var b bytes.Buffer
		err := binary.Write(&b, binary.BigEndian, k.Bool())
		return fmt.Sprintf("%t", k.Bool()), b.Bytes(), err

		// platform-length integers
	case reflect.Int:
		// extend platform dependent Int into fixed-length Int64
		return keyNames(k.Int(), keyLength)
	case reflect.Uint:
		// extend platform dependent Uint into fixed-length Uint64
		return keyNames(k.Uint(), keyLength)

		// fixed-length integers
	case reflect.Int8:
		fallthrough
	case reflect.Int16:
		fallthrough
	case reflect.Int32:
		fallthrough
	case reflect.Int64:
		fallthrough
	case reflect.Uint8:
		fallthrough
	case reflect.Uint16:
		fallthrough
	case reflect.Uint32:
		fallthrough
	case reflect.Uint64:
		var b bytes.Buffer
		err := binary.Write(&b, binary.BigEndian, k.Interface())
		return fmt.Sprintf("%d", k.Interface()), b.Bytes(), err
	}

	return "", nil, fmt.Errorf("unsupported key type: %T", key)
}
