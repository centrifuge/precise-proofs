// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proofs/proto/proof.proto

package proofspb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import descriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type MerkleHash struct {
	Left                 []byte   `protobuf:"bytes,1,opt,name=left,proto3" json:"left,omitempty"`
	Right                []byte   `protobuf:"bytes,2,opt,name=right,proto3" json:"right,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MerkleHash) Reset()         { *m = MerkleHash{} }
func (m *MerkleHash) String() string { return proto.CompactTextString(m) }
func (*MerkleHash) ProtoMessage()    {}
func (*MerkleHash) Descriptor() ([]byte, []int) {
	return fileDescriptor_proof_da0cc266346c2a2a, []int{0}
}
func (m *MerkleHash) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MerkleHash.Unmarshal(m, b)
}
func (m *MerkleHash) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MerkleHash.Marshal(b, m, deterministic)
}
func (dst *MerkleHash) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MerkleHash.Merge(dst, src)
}
func (m *MerkleHash) XXX_Size() int {
	return xxx_messageInfo_MerkleHash.Size(m)
}
func (m *MerkleHash) XXX_DiscardUnknown() {
	xxx_messageInfo_MerkleHash.DiscardUnknown(m)
}

var xxx_messageInfo_MerkleHash proto.InternalMessageInfo

func (m *MerkleHash) GetLeft() []byte {
	if m != nil {
		return m.Left
	}
	return nil
}

func (m *MerkleHash) GetRight() []byte {
	if m != nil {
		return m.Right
	}
	return nil
}

type Proof struct {
	// Types that are valid to be assigned to Property:
	//	*Proof_ReadableName
	//	*Proof_CompactName
	Property isProof_Property `protobuf_oneof:"property"`
	Value    string           `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
	Salt     []byte           `protobuf:"bytes,3,opt,name=salt,proto3" json:"salt,omitempty"`
	// hash is filled if value & salt are not available
	Hash []byte `protobuf:"bytes,6,opt,name=hash,proto3" json:"hash,omitempty"`
	// Fills either 'hashes' for standard Merkle trees or 'sorted_hashes' for a lexicograhical ordered of a node hash
	// not both
	Hashes               []*MerkleHash `protobuf:"bytes,4,rep,name=hashes" json:"hashes,omitempty"`
	SortedHashes         [][]byte      `protobuf:"bytes,5,rep,name=sorted_hashes,json=sortedHashes,proto3" json:"sorted_hashes,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Proof) Reset()         { *m = Proof{} }
func (m *Proof) String() string { return proto.CompactTextString(m) }
func (*Proof) ProtoMessage()    {}
func (*Proof) Descriptor() ([]byte, []int) {
	return fileDescriptor_proof_da0cc266346c2a2a, []int{1}
}
func (m *Proof) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Proof.Unmarshal(m, b)
}
func (m *Proof) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Proof.Marshal(b, m, deterministic)
}
func (dst *Proof) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Proof.Merge(dst, src)
}
func (m *Proof) XXX_Size() int {
	return xxx_messageInfo_Proof.Size(m)
}
func (m *Proof) XXX_DiscardUnknown() {
	xxx_messageInfo_Proof.DiscardUnknown(m)
}

var xxx_messageInfo_Proof proto.InternalMessageInfo

type isProof_Property interface {
	isProof_Property()
}

type Proof_ReadableName struct {
	ReadableName string `protobuf:"bytes,7,opt,name=readable_name,json=readableName,oneof"`
}
type Proof_CompactName struct {
	CompactName *FieldNums `protobuf:"bytes,9,opt,name=compact_name,json=compactName,oneof"`
}

func (*Proof_ReadableName) isProof_Property() {}
func (*Proof_CompactName) isProof_Property()  {}

func (m *Proof) GetProperty() isProof_Property {
	if m != nil {
		return m.Property
	}
	return nil
}

func (m *Proof) GetReadableName() string {
	if x, ok := m.GetProperty().(*Proof_ReadableName); ok {
		return x.ReadableName
	}
	return ""
}

func (m *Proof) GetCompactName() *FieldNums {
	if x, ok := m.GetProperty().(*Proof_CompactName); ok {
		return x.CompactName
	}
	return nil
}

func (m *Proof) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

func (m *Proof) GetSalt() []byte {
	if m != nil {
		return m.Salt
	}
	return nil
}

func (m *Proof) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *Proof) GetHashes() []*MerkleHash {
	if m != nil {
		return m.Hashes
	}
	return nil
}

func (m *Proof) GetSortedHashes() [][]byte {
	if m != nil {
		return m.SortedHashes
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Proof) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Proof_OneofMarshaler, _Proof_OneofUnmarshaler, _Proof_OneofSizer, []interface{}{
		(*Proof_ReadableName)(nil),
		(*Proof_CompactName)(nil),
	}
}

func _Proof_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Proof)
	// property
	switch x := m.Property.(type) {
	case *Proof_ReadableName:
		b.EncodeVarint(7<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.ReadableName)
	case *Proof_CompactName:
		b.EncodeVarint(9<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.CompactName); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Proof.Property has unexpected type %T", x)
	}
	return nil
}

func _Proof_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Proof)
	switch tag {
	case 7: // property.readable_name
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Property = &Proof_ReadableName{x}
		return true, err
	case 9: // property.compact_name
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(FieldNums)
		err := b.DecodeMessage(msg)
		m.Property = &Proof_CompactName{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Proof_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Proof)
	// property
	switch x := m.Property.(type) {
	case *Proof_ReadableName:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.ReadableName)))
		n += len(x.ReadableName)
	case *Proof_CompactName:
		s := proto.Size(x.CompactName)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type FieldNums struct {
	Components           []uint64 `protobuf:"varint,1,rep,packed,name=components" json:"components,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FieldNums) Reset()         { *m = FieldNums{} }
func (m *FieldNums) String() string { return proto.CompactTextString(m) }
func (*FieldNums) ProtoMessage()    {}
func (*FieldNums) Descriptor() ([]byte, []int) {
	return fileDescriptor_proof_da0cc266346c2a2a, []int{2}
}
func (m *FieldNums) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FieldNums.Unmarshal(m, b)
}
func (m *FieldNums) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FieldNums.Marshal(b, m, deterministic)
}
func (dst *FieldNums) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FieldNums.Merge(dst, src)
}
func (m *FieldNums) XXX_Size() int {
	return xxx_messageInfo_FieldNums.Size(m)
}
func (m *FieldNums) XXX_DiscardUnknown() {
	xxx_messageInfo_FieldNums.DiscardUnknown(m)
}

var xxx_messageInfo_FieldNums proto.InternalMessageInfo

func (m *FieldNums) GetComponents() []uint64 {
	if m != nil {
		return m.Components
	}
	return nil
}

var E_ExcludeFromTree = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         2862100,
	Name:          "proofs.exclude_from_tree",
	Tag:           "varint,2862100,opt,name=exclude_from_tree,json=excludeFromTree",
	Filename:      "proofs/proto/proof.proto",
}

var E_HashedField = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*bool)(nil),
	Field:         2862101,
	Name:          "proofs.hashed_field",
	Tag:           "varint,2862101,opt,name=hashed_field,json=hashedField",
	Filename:      "proofs/proto/proof.proto",
}

func init() {
	proto.RegisterType((*MerkleHash)(nil), "proofs.MerkleHash")
	proto.RegisterType((*Proof)(nil), "proofs.Proof")
	proto.RegisterType((*FieldNums)(nil), "proofs.FieldNums")
	proto.RegisterExtension(E_ExcludeFromTree)
	proto.RegisterExtension(E_HashedField)
}

func init() { proto.RegisterFile("proofs/proto/proof.proto", fileDescriptor_proof_da0cc266346c2a2a) }

var fileDescriptor_proof_da0cc266346c2a2a = []byte{
	// 403 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x51, 0x4d, 0x8b, 0xd4, 0x40,
	0x10, 0xdd, 0xec, 0x7c, 0x38, 0x53, 0x93, 0x45, 0xb6, 0xd9, 0x43, 0x23, 0x28, 0x61, 0x54, 0x08,
	0x0a, 0x19, 0x58, 0x61, 0x0f, 0x7b, 0x1c, 0x61, 0x99, 0x83, 0xae, 0x43, 0xe3, 0xc9, 0x4b, 0xe8,
	0x24, 0x95, 0x49, 0xb0, 0x93, 0x6e, 0xba, 0x3b, 0xa2, 0x47, 0xff, 0x83, 0xfe, 0x0d, 0x7f, 0x8f,
	0x3f, 0x47, 0xba, 0x3b, 0x51, 0x6f, 0x7b, 0x4a, 0xd5, 0xeb, 0xf7, 0xaa, 0x5e, 0xea, 0x01, 0x55,
	0x5a, 0xca, 0xda, 0xec, 0x94, 0x96, 0x56, 0xee, 0x7c, 0x93, 0xf9, 0x9a, 0x2c, 0xc3, 0xcb, 0x93,
	0xe4, 0x24, 0xe5, 0x49, 0x60, 0x60, 0x14, 0x43, 0xbd, 0xab, 0xd0, 0x94, 0xba, 0x55, 0x56, 0xea,
	0xc0, 0xdc, 0xde, 0x00, 0xbc, 0x47, 0xfd, 0x59, 0xe0, 0x81, 0x9b, 0x86, 0x10, 0x98, 0x0b, 0xac,
	0x2d, 0x8d, 0x92, 0x28, 0x8d, 0x99, 0xaf, 0xc9, 0x15, 0x2c, 0x74, 0x7b, 0x6a, 0x2c, 0x3d, 0xf7,
	0x60, 0x68, 0xb6, 0xdf, 0xcf, 0x61, 0x71, 0x74, 0x4b, 0xc8, 0x4b, 0xb8, 0xd0, 0xc8, 0x2b, 0x5e,
	0x08, 0xcc, 0x7b, 0xde, 0x21, 0x7d, 0x94, 0x44, 0xe9, 0xfa, 0x70, 0xc6, 0xe2, 0x09, 0xbe, 0xe7,
	0x1d, 0x92, 0x1b, 0x88, 0x4b, 0xd9, 0x29, 0x5e, 0xda, 0xc0, 0x5a, 0x27, 0x51, 0xba, 0xb9, 0xbe,
	0xcc, 0x82, 0xd3, 0xec, 0xae, 0x45, 0x51, 0xdd, 0x0f, 0x9d, 0x39, 0x9c, 0xb1, 0xcd, 0x48, 0xf4,
	0xba, 0x2b, 0x58, 0x7c, 0xe1, 0x62, 0x40, 0xbf, 0x7e, 0xcd, 0x42, 0xe3, 0x8c, 0x1a, 0x2e, 0x2c,
	0x9d, 0x05, 0xa3, 0xae, 0x76, 0x58, 0xc3, 0x4d, 0x43, 0x97, 0x01, 0x73, 0x35, 0x79, 0x05, 0x4b,
	0xf7, 0x45, 0x43, 0xe7, 0xc9, 0x2c, 0xdd, 0x5c, 0x93, 0x69, 0xdf, 0xbf, 0x9f, 0x66, 0x23, 0x83,
	0x3c, 0x87, 0x0b, 0x23, 0xb5, 0xc5, 0x2a, 0x1f, 0x25, 0x8b, 0x64, 0x96, 0xc6, 0x2c, 0x0e, 0xe0,
	0xc1, 0x63, 0x7b, 0x80, 0x95, 0xd2, 0x52, 0xa1, 0xb6, 0xdf, 0xb6, 0xaf, 0x61, 0xfd, 0xd7, 0x36,
	0x79, 0x06, 0xe0, 0x6c, 0xcb, 0x1e, 0x7b, 0x6b, 0x68, 0x94, 0xcc, 0xd2, 0x39, 0xfb, 0x0f, 0xb9,
	0x7d, 0x07, 0x97, 0xf8, 0xb5, 0x14, 0x43, 0x85, 0x79, 0xad, 0x65, 0x97, 0x5b, 0x8d, 0x48, 0x9e,
	0x66, 0x21, 0xa0, 0x6c, 0x0a, 0x28, 0xdc, 0xe1, 0x83, 0xb2, 0xad, 0xec, 0x0d, 0xfd, 0xf1, 0xfb,
	0x97, 0x4b, 0x62, 0xc5, 0x1e, 0x8f, 0xd2, 0x3b, 0x2d, 0xbb, 0x8f, 0x1a, 0xf1, 0xf6, 0x2d, 0xc4,
	0xde, 0x64, 0x95, 0xd7, 0x4e, 0xf0, 0xd0, 0xa0, 0x9f, 0xd3, 0xa0, 0x4d, 0x50, 0xf9, 0xc7, 0xfd,
	0x0b, 0x6f, 0x79, 0xbc, 0xc8, 0x1e, 0x7c, 0x9c, 0x47, 0xa7, 0x3f, 0x46, 0x9f, 0x56, 0x01, 0x55,
	0x45, 0xb1, 0xf4, 0x23, 0xdf, 0xfc, 0x09, 0x00, 0x00, 0xff, 0xff, 0xe9, 0xc3, 0xda, 0x02, 0x6e,
	0x02, 0x00, 0x00,
}
