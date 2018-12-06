package proofs

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

// SliceElemFormat represents how the property name of a slice element is derived from its parent
const SliceElemFormat = "%s[%s]"

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

// ElemProp takes a repeated field index and returns a child Property representing that element of the repeated field
func (n Property) ElemProp(i FieldNum) Property {
	return Property{
		Parent:     &n,
		Text:       fmt.Sprintf("%d", i),
		Nums:       []FieldNum{i},
		NameFormat: SliceElemFormat,
	}
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
