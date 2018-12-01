package proofs

import (
    "fmt"
    "bytes"
    "encoding/binary"
)

// PropertyName is a []byte-convertible name of a Property. A PropertyName can be extracted from a Property using a compact or human-readable encoding
type PropertyName interface {
    AsBytes() []byte
}

// FieldNumPath is a compact PropertyName
type FieldNumPath []FieldNum

// AsBytes encodes a FieldNumPath using big endian encoding
func (pn FieldNumPath) AsBytes() []byte {
    buf := new(bytes.Buffer)
    binary.Write(buf, binary.BigEndian, pn)
    fmt.Println(pn, "as bytes is", buf.Bytes())
    return buf.Bytes()
}

func (pn FieldNumPath) String() string {
    return fmt.Sprint([]FieldNum(pn))
}

// FieldNamePath is a human-readable PropertyName
type FieldNamePath string

// AsBytes encodes a FieldNamePath using the individual bytes of the string
func (pn FieldNamePath) AsBytes() []byte {
    return []byte(pn)
}

// LiteralPropName is a literal encoding of a PropertyName. This is useful if you have a []byte used for a hash, but don't know how it was generated
type LiteralPropName []byte

func (pn LiteralPropName) AsBytes() []byte {
    return pn
}
