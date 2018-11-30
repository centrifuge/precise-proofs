package proofs

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// Property uniquely identifies a node in a nested data structure
type Property struct {
	Parent     *Property
	Text       string
	Ordinal    *OrdNum
	NameFormat string
}

// SubFieldFormat represents how the property name of a struct field is derived from its parent
const SubFieldFormat = "%s.%s"

// SliceElemFormat represents how the property name of a slice element is derived from its parent
const SliceElemFormat = "%s[%s]"

// OrdNum is a single component of a compact property name
type OrdNum uint64

func (n *Property) String() string {
	return n.Name()
}

// Name returns the human-readable name of a property
func (n *Property) Name() string {
	if n.Parent == nil {
		return n.Text
	}
	return fmt.Sprintf(n.NameFormat, n.Parent.Name(), n.Text)
}

// CompactName returns the compact name of a property, derived from protobuf tags
func (n *Property) CompactName() []byte {
	if n == nil {
		return nil
	}
	var bs []byte
	if n.Ordinal != nil {
		bs = make([]byte, binary.Size(*n.Ordinal))
		binary.BigEndian.PutUint64(bs, uint64(*n.Ordinal))
	}
	return append(n.Parent.CompactName(), bs...)
}

// FieldProp takes the protobuf tag string of a struct field and returns a child Property representing that field of the struct
func (n *Property) FieldProp(protobufTag string) (field Property, err error) {
	field.Parent = n

	tagList := strings.Split(protobufTag, ",")
	if len(tagList) < 4 {
		err = errors.New("not enough elements in protobuf tag list")
		return field, err
	}

	// first element describes field encoding: bytes, varint, etc.
	// second element is the field ordinal number
	var ord uint64
	ord, err = strconv.ParseUint(tagList[1], 10, 64)
	if err != nil {
		err = errors.Wrap(err, "error parsing ordinal tag")
		return field, err
	}
	field.Ordinal = (*OrdNum)(&ord)

	// third element describes optionality of the field
	// fourth element has protobuf field name: e.g. 'name=ThisField'
	field.Text = strings.TrimPrefix(tagList[3], "name=")

	// other fields exist, but aren't needed

	field.NameFormat = SubFieldFormat

	return field, err
}

// ElemProp takes a repeated field index and returns a child Property representing that element of the repeated field
func (n *Property) ElemProp(i OrdNum) Property {
	return Property{
		Parent:     n,
		Text:       fmt.Sprintf("%d", i),
		Ordinal:    &i,
		NameFormat: SliceElemFormat,
	}
}

// LengthProp returns a child Property representing the length of a repeated field
func (n *Property) LengthProp() Property {
	return Property{
		Parent:     n,
		Text:       "length",
		NameFormat: SubFieldFormat,
	}
}
