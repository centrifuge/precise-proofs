// Code generated by protoc-gen-go. DO NOT EDIT.
// source: examples/documents/example.proto

package documents // import "github.com/centrifuge/precise-proofs/examples/documents"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import timestamp "github.com/golang/protobuf/ptypes/timestamp"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type ExampleDocument struct {
	ValueA               string   `protobuf:"bytes,1,opt,name=ValueA" json:"ValueA,omitempty"`
	ValueB               string   `protobuf:"bytes,2,opt,name=ValueB" json:"ValueB,omitempty"`
	Value1               int64    `protobuf:"varint,3,opt,name=Value1" json:"Value1,omitempty"`
	Value2               int64    `protobuf:"varint,4,opt,name=Value2" json:"Value2,omitempty"`
	ValueBytes1          []byte   `protobuf:"bytes,5,opt,name=ValueBytes1,proto3" json:"ValueBytes1,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExampleDocument) Reset()         { *m = ExampleDocument{} }
func (m *ExampleDocument) String() string { return proto.CompactTextString(m) }
func (*ExampleDocument) ProtoMessage()    {}
func (*ExampleDocument) Descriptor() ([]byte, []int) {
	return fileDescriptor_example_dadf98cda8fd3933, []int{0}
}
func (m *ExampleDocument) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExampleDocument.Unmarshal(m, b)
}
func (m *ExampleDocument) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExampleDocument.Marshal(b, m, deterministic)
}
func (dst *ExampleDocument) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExampleDocument.Merge(dst, src)
}
func (m *ExampleDocument) XXX_Size() int {
	return xxx_messageInfo_ExampleDocument.Size(m)
}
func (m *ExampleDocument) XXX_DiscardUnknown() {
	xxx_messageInfo_ExampleDocument.DiscardUnknown(m)
}

var xxx_messageInfo_ExampleDocument proto.InternalMessageInfo

func (m *ExampleDocument) GetValueA() string {
	if m != nil {
		return m.ValueA
	}
	return ""
}

func (m *ExampleDocument) GetValueB() string {
	if m != nil {
		return m.ValueB
	}
	return ""
}

func (m *ExampleDocument) GetValue1() int64 {
	if m != nil {
		return m.Value1
	}
	return 0
}

func (m *ExampleDocument) GetValue2() int64 {
	if m != nil {
		return m.Value2
	}
	return 0
}

func (m *ExampleDocument) GetValueBytes1() []byte {
	if m != nil {
		return m.ValueBytes1
	}
	return nil
}

type AllFieldTypes struct {
	StringValue          string               `protobuf:"bytes,1,opt,name=StringValue" json:"StringValue,omitempty"`
	TimestampValue       *timestamp.Timestamp `protobuf:"bytes,2,opt,name=TimestampValue" json:"TimestampValue,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *AllFieldTypes) Reset()         { *m = AllFieldTypes{} }
func (m *AllFieldTypes) String() string { return proto.CompactTextString(m) }
func (*AllFieldTypes) ProtoMessage()    {}
func (*AllFieldTypes) Descriptor() ([]byte, []int) {
	return fileDescriptor_example_dadf98cda8fd3933, []int{1}
}
func (m *AllFieldTypes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AllFieldTypes.Unmarshal(m, b)
}
func (m *AllFieldTypes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AllFieldTypes.Marshal(b, m, deterministic)
}
func (dst *AllFieldTypes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AllFieldTypes.Merge(dst, src)
}
func (m *AllFieldTypes) XXX_Size() int {
	return xxx_messageInfo_AllFieldTypes.Size(m)
}
func (m *AllFieldTypes) XXX_DiscardUnknown() {
	xxx_messageInfo_AllFieldTypes.DiscardUnknown(m)
}

var xxx_messageInfo_AllFieldTypes proto.InternalMessageInfo

func (m *AllFieldTypes) GetStringValue() string {
	if m != nil {
		return m.StringValue
	}
	return ""
}

func (m *AllFieldTypes) GetTimestampValue() *timestamp.Timestamp {
	if m != nil {
		return m.TimestampValue
	}
	return nil
}

type AllFieldTypesSalts struct {
	StringValue          []byte   `protobuf:"bytes,1,opt,name=StringValue,proto3" json:"StringValue,omitempty"`
	TimestampValue       []byte   `protobuf:"bytes,2,opt,name=TimestampValue,proto3" json:"TimestampValue,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AllFieldTypesSalts) Reset()         { *m = AllFieldTypesSalts{} }
func (m *AllFieldTypesSalts) String() string { return proto.CompactTextString(m) }
func (*AllFieldTypesSalts) ProtoMessage()    {}
func (*AllFieldTypesSalts) Descriptor() ([]byte, []int) {
	return fileDescriptor_example_dadf98cda8fd3933, []int{2}
}
func (m *AllFieldTypesSalts) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AllFieldTypesSalts.Unmarshal(m, b)
}
func (m *AllFieldTypesSalts) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AllFieldTypesSalts.Marshal(b, m, deterministic)
}
func (dst *AllFieldTypesSalts) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AllFieldTypesSalts.Merge(dst, src)
}
func (m *AllFieldTypesSalts) XXX_Size() int {
	return xxx_messageInfo_AllFieldTypesSalts.Size(m)
}
func (m *AllFieldTypesSalts) XXX_DiscardUnknown() {
	xxx_messageInfo_AllFieldTypesSalts.DiscardUnknown(m)
}

var xxx_messageInfo_AllFieldTypesSalts proto.InternalMessageInfo

func (m *AllFieldTypesSalts) GetStringValue() []byte {
	if m != nil {
		return m.StringValue
	}
	return nil
}

func (m *AllFieldTypesSalts) GetTimestampValue() []byte {
	if m != nil {
		return m.TimestampValue
	}
	return nil
}

type LongDocument struct {
	Value0               int64    `protobuf:"varint,16,opt,name=Value0" json:"Value0,omitempty"`
	Value1               int64    `protobuf:"varint,1,opt,name=Value1" json:"Value1,omitempty"`
	Value2               int64    `protobuf:"varint,2,opt,name=Value2" json:"Value2,omitempty"`
	Value3               int64    `protobuf:"varint,3,opt,name=Value3" json:"Value3,omitempty"`
	Value4               int64    `protobuf:"varint,4,opt,name=Value4" json:"Value4,omitempty"`
	Value5               int64    `protobuf:"varint,5,opt,name=Value5" json:"Value5,omitempty"`
	Value6               int64    `protobuf:"varint,6,opt,name=Value6" json:"Value6,omitempty"`
	Value7               int64    `protobuf:"varint,7,opt,name=Value7" json:"Value7,omitempty"`
	Value8               int64    `protobuf:"varint,8,opt,name=Value8" json:"Value8,omitempty"`
	Value9               int64    `protobuf:"varint,9,opt,name=Value9" json:"Value9,omitempty"`
	ValueA               int64    `protobuf:"varint,10,opt,name=ValueA" json:"ValueA,omitempty"`
	ValueB               int64    `protobuf:"varint,11,opt,name=ValueB" json:"ValueB,omitempty"`
	ValueC               int64    `protobuf:"varint,12,opt,name=ValueC" json:"ValueC,omitempty"`
	ValueD               int64    `protobuf:"varint,13,opt,name=ValueD" json:"ValueD,omitempty"`
	ValueE               int64    `protobuf:"varint,14,opt,name=ValueE" json:"ValueE,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LongDocument) Reset()         { *m = LongDocument{} }
func (m *LongDocument) String() string { return proto.CompactTextString(m) }
func (*LongDocument) ProtoMessage()    {}
func (*LongDocument) Descriptor() ([]byte, []int) {
	return fileDescriptor_example_dadf98cda8fd3933, []int{3}
}
func (m *LongDocument) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LongDocument.Unmarshal(m, b)
}
func (m *LongDocument) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LongDocument.Marshal(b, m, deterministic)
}
func (dst *LongDocument) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LongDocument.Merge(dst, src)
}
func (m *LongDocument) XXX_Size() int {
	return xxx_messageInfo_LongDocument.Size(m)
}
func (m *LongDocument) XXX_DiscardUnknown() {
	xxx_messageInfo_LongDocument.DiscardUnknown(m)
}

var xxx_messageInfo_LongDocument proto.InternalMessageInfo

func (m *LongDocument) GetValue0() int64 {
	if m != nil {
		return m.Value0
	}
	return 0
}

func (m *LongDocument) GetValue1() int64 {
	if m != nil {
		return m.Value1
	}
	return 0
}

func (m *LongDocument) GetValue2() int64 {
	if m != nil {
		return m.Value2
	}
	return 0
}

func (m *LongDocument) GetValue3() int64 {
	if m != nil {
		return m.Value3
	}
	return 0
}

func (m *LongDocument) GetValue4() int64 {
	if m != nil {
		return m.Value4
	}
	return 0
}

func (m *LongDocument) GetValue5() int64 {
	if m != nil {
		return m.Value5
	}
	return 0
}

func (m *LongDocument) GetValue6() int64 {
	if m != nil {
		return m.Value6
	}
	return 0
}

func (m *LongDocument) GetValue7() int64 {
	if m != nil {
		return m.Value7
	}
	return 0
}

func (m *LongDocument) GetValue8() int64 {
	if m != nil {
		return m.Value8
	}
	return 0
}

func (m *LongDocument) GetValue9() int64 {
	if m != nil {
		return m.Value9
	}
	return 0
}

func (m *LongDocument) GetValueA() int64 {
	if m != nil {
		return m.ValueA
	}
	return 0
}

func (m *LongDocument) GetValueB() int64 {
	if m != nil {
		return m.ValueB
	}
	return 0
}

func (m *LongDocument) GetValueC() int64 {
	if m != nil {
		return m.ValueC
	}
	return 0
}

func (m *LongDocument) GetValueD() int64 {
	if m != nil {
		return m.ValueD
	}
	return 0
}

func (m *LongDocument) GetValueE() int64 {
	if m != nil {
		return m.ValueE
	}
	return 0
}

type SaltedLongDocument struct {
	Value0               []byte   `protobuf:"bytes,16,opt,name=Value0,proto3" json:"Value0,omitempty"`
	Value1               []byte   `protobuf:"bytes,1,opt,name=Value1,proto3" json:"Value1,omitempty"`
	Value2               []byte   `protobuf:"bytes,2,opt,name=Value2,proto3" json:"Value2,omitempty"`
	Value3               []byte   `protobuf:"bytes,3,opt,name=Value3,proto3" json:"Value3,omitempty"`
	Value4               []byte   `protobuf:"bytes,4,opt,name=Value4,proto3" json:"Value4,omitempty"`
	Value5               []byte   `protobuf:"bytes,5,opt,name=Value5,proto3" json:"Value5,omitempty"`
	Value6               []byte   `protobuf:"bytes,6,opt,name=Value6,proto3" json:"Value6,omitempty"`
	Value7               []byte   `protobuf:"bytes,7,opt,name=Value7,proto3" json:"Value7,omitempty"`
	Value8               []byte   `protobuf:"bytes,8,opt,name=Value8,proto3" json:"Value8,omitempty"`
	Value9               []byte   `protobuf:"bytes,9,opt,name=Value9,proto3" json:"Value9,omitempty"`
	ValueA               []byte   `protobuf:"bytes,10,opt,name=ValueA,proto3" json:"ValueA,omitempty"`
	ValueB               []byte   `protobuf:"bytes,11,opt,name=ValueB,proto3" json:"ValueB,omitempty"`
	ValueC               []byte   `protobuf:"bytes,12,opt,name=ValueC,proto3" json:"ValueC,omitempty"`
	ValueD               []byte   `protobuf:"bytes,13,opt,name=ValueD,proto3" json:"ValueD,omitempty"`
	ValueE               []byte   `protobuf:"bytes,14,opt,name=ValueE,proto3" json:"ValueE,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SaltedLongDocument) Reset()         { *m = SaltedLongDocument{} }
func (m *SaltedLongDocument) String() string { return proto.CompactTextString(m) }
func (*SaltedLongDocument) ProtoMessage()    {}
func (*SaltedLongDocument) Descriptor() ([]byte, []int) {
	return fileDescriptor_example_dadf98cda8fd3933, []int{4}
}
func (m *SaltedLongDocument) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SaltedLongDocument.Unmarshal(m, b)
}
func (m *SaltedLongDocument) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SaltedLongDocument.Marshal(b, m, deterministic)
}
func (dst *SaltedLongDocument) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SaltedLongDocument.Merge(dst, src)
}
func (m *SaltedLongDocument) XXX_Size() int {
	return xxx_messageInfo_SaltedLongDocument.Size(m)
}
func (m *SaltedLongDocument) XXX_DiscardUnknown() {
	xxx_messageInfo_SaltedLongDocument.DiscardUnknown(m)
}

var xxx_messageInfo_SaltedLongDocument proto.InternalMessageInfo

func (m *SaltedLongDocument) GetValue0() []byte {
	if m != nil {
		return m.Value0
	}
	return nil
}

func (m *SaltedLongDocument) GetValue1() []byte {
	if m != nil {
		return m.Value1
	}
	return nil
}

func (m *SaltedLongDocument) GetValue2() []byte {
	if m != nil {
		return m.Value2
	}
	return nil
}

func (m *SaltedLongDocument) GetValue3() []byte {
	if m != nil {
		return m.Value3
	}
	return nil
}

func (m *SaltedLongDocument) GetValue4() []byte {
	if m != nil {
		return m.Value4
	}
	return nil
}

func (m *SaltedLongDocument) GetValue5() []byte {
	if m != nil {
		return m.Value5
	}
	return nil
}

func (m *SaltedLongDocument) GetValue6() []byte {
	if m != nil {
		return m.Value6
	}
	return nil
}

func (m *SaltedLongDocument) GetValue7() []byte {
	if m != nil {
		return m.Value7
	}
	return nil
}

func (m *SaltedLongDocument) GetValue8() []byte {
	if m != nil {
		return m.Value8
	}
	return nil
}

func (m *SaltedLongDocument) GetValue9() []byte {
	if m != nil {
		return m.Value9
	}
	return nil
}

func (m *SaltedLongDocument) GetValueA() []byte {
	if m != nil {
		return m.ValueA
	}
	return nil
}

func (m *SaltedLongDocument) GetValueB() []byte {
	if m != nil {
		return m.ValueB
	}
	return nil
}

func (m *SaltedLongDocument) GetValueC() []byte {
	if m != nil {
		return m.ValueC
	}
	return nil
}

func (m *SaltedLongDocument) GetValueD() []byte {
	if m != nil {
		return m.ValueD
	}
	return nil
}

func (m *SaltedLongDocument) GetValueE() []byte {
	if m != nil {
		return m.ValueE
	}
	return nil
}

type SaltedExampleDocument struct {
	ValueA               []byte   `protobuf:"bytes,1,opt,name=ValueA,proto3" json:"ValueA,omitempty"`
	ValueB               []byte   `protobuf:"bytes,2,opt,name=ValueB,proto3" json:"ValueB,omitempty"`
	Value1               []byte   `protobuf:"bytes,3,opt,name=Value1,proto3" json:"Value1,omitempty"`
	Value2               []byte   `protobuf:"bytes,4,opt,name=Value2,proto3" json:"Value2,omitempty"`
	ValueBytes1          []byte   `protobuf:"bytes,5,opt,name=ValueBytes1,proto3" json:"ValueBytes1,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SaltedExampleDocument) Reset()         { *m = SaltedExampleDocument{} }
func (m *SaltedExampleDocument) String() string { return proto.CompactTextString(m) }
func (*SaltedExampleDocument) ProtoMessage()    {}
func (*SaltedExampleDocument) Descriptor() ([]byte, []int) {
	return fileDescriptor_example_dadf98cda8fd3933, []int{5}
}
func (m *SaltedExampleDocument) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SaltedExampleDocument.Unmarshal(m, b)
}
func (m *SaltedExampleDocument) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SaltedExampleDocument.Marshal(b, m, deterministic)
}
func (dst *SaltedExampleDocument) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SaltedExampleDocument.Merge(dst, src)
}
func (m *SaltedExampleDocument) XXX_Size() int {
	return xxx_messageInfo_SaltedExampleDocument.Size(m)
}
func (m *SaltedExampleDocument) XXX_DiscardUnknown() {
	xxx_messageInfo_SaltedExampleDocument.DiscardUnknown(m)
}

var xxx_messageInfo_SaltedExampleDocument proto.InternalMessageInfo

func (m *SaltedExampleDocument) GetValueA() []byte {
	if m != nil {
		return m.ValueA
	}
	return nil
}

func (m *SaltedExampleDocument) GetValueB() []byte {
	if m != nil {
		return m.ValueB
	}
	return nil
}

func (m *SaltedExampleDocument) GetValue1() []byte {
	if m != nil {
		return m.Value1
	}
	return nil
}

func (m *SaltedExampleDocument) GetValue2() []byte {
	if m != nil {
		return m.Value2
	}
	return nil
}

func (m *SaltedExampleDocument) GetValueBytes1() []byte {
	if m != nil {
		return m.ValueBytes1
	}
	return nil
}

func init() {
	proto.RegisterType((*ExampleDocument)(nil), "documents.ExampleDocument")
	proto.RegisterType((*AllFieldTypes)(nil), "documents.AllFieldTypes")
	proto.RegisterType((*AllFieldTypesSalts)(nil), "documents.AllFieldTypesSalts")
	proto.RegisterType((*LongDocument)(nil), "documents.LongDocument")
	proto.RegisterType((*SaltedLongDocument)(nil), "documents.SaltedLongDocument")
	proto.RegisterType((*SaltedExampleDocument)(nil), "documents.SaltedExampleDocument")
}

func init() {
	proto.RegisterFile("examples/documents/example.proto", fileDescriptor_example_dadf98cda8fd3933)
}

var fileDescriptor_example_dadf98cda8fd3933 = []byte{
	// 460 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x94, 0xcf, 0x6e, 0xd3, 0x40,
	0x10, 0x87, 0x65, 0x17, 0x02, 0xd9, 0x4c, 0x0b, 0xb2, 0x04, 0x5a, 0xf5, 0x82, 0xe5, 0x03, 0xca,
	0x05, 0xbb, 0x49, 0xda, 0xa6, 0x39, 0xd6, 0x4d, 0x38, 0x71, 0x4a, 0x2b, 0x0e, 0x1c, 0x90, 0x1c,
	0x67, 0x63, 0x2c, 0xd9, 0x5e, 0xcb, 0x5e, 0x4b, 0xf4, 0x39, 0x38, 0xf1, 0xa2, 0x9c, 0x38, 0x20,
	0xff, 0x5b, 0xc6, 0xb4, 0x53, 0x71, 0xcc, 0xb7, 0x33, 0x99, 0xf5, 0xb7, 0xa3, 0x1f, 0xb3, 0xc5,
	0xf7, 0x20, 0xcd, 0x13, 0x51, 0x7a, 0x7b, 0x19, 0x56, 0xa9, 0xc8, 0x54, 0xe9, 0x75, 0xc8, 0xcd,
	0x0b, 0xa9, 0xa4, 0x35, 0xd6, 0x07, 0xa7, 0xef, 0x22, 0x29, 0xa3, 0x44, 0x78, 0xcd, 0xc1, 0xae,
	0x3a, 0x78, 0x2a, 0x4e, 0x45, 0xa9, 0x82, 0x34, 0x6f, 0x6b, 0x9d, 0x1f, 0x06, 0x7b, 0xb5, 0x69,
	0xbb, 0xd7, 0x5d, 0x97, 0xf5, 0x96, 0x8d, 0x3e, 0x07, 0x49, 0x25, 0xae, 0xb9, 0x61, 0x1b, 0xd3,
	0xf1, 0xb6, 0xfb, 0xa5, 0xb9, 0xcf, 0x4d, 0xc4, 0x7d, 0xcd, 0x67, 0xfc, 0xc8, 0x36, 0xa6, 0x47,
	0x1d, 0x9f, 0x69, 0x3e, 0xe7, 0xcf, 0x10, 0x9f, 0x5b, 0x36, 0x9b, 0xb4, 0x9d, 0xf7, 0x4a, 0x94,
	0x33, 0xfe, 0xdc, 0x36, 0xa6, 0xb0, 0xc5, 0xc8, 0xa9, 0xd8, 0xf1, 0x75, 0x92, 0x7c, 0x8c, 0x45,
	0xb2, 0xbf, 0xbb, 0xcf, 0x45, 0x59, 0xb7, 0xdc, 0xaa, 0x22, 0xce, 0xa2, 0xa6, 0xaa, 0xbb, 0x17,
	0x46, 0x96, 0xcf, 0x4e, 0xee, 0xfa, 0x6f, 0x6b, 0x8b, 0xea, 0x4b, 0x4e, 0xe6, 0xa7, 0x6e, 0xab,
	0xc0, 0xed, 0x15, 0xb8, 0xba, 0x6c, 0xfb, 0x4f, 0x87, 0xf3, 0x95, 0x59, 0x83, 0xb1, 0xb7, 0x41,
	0xa2, 0x1e, 0x9d, 0x0d, 0xc3, 0xd9, 0xef, 0x1f, 0x9d, 0x0d, 0x0f, 0xfe, 0xff, 0x97, 0xc9, 0xe0,
	0x93, 0xcc, 0xa2, 0x07, 0xa6, 0xcf, 0xf8, 0x6b, 0x64, 0xe8, 0x0c, 0x19, 0x35, 0x08, 0xa3, 0xe6,
	0xc0, 0x68, 0xcf, 0x17, 0x83, 0x17, 0x58, 0x68, 0x7e, 0x3e, 0x78, 0x81, 0x73, 0xcd, 0x2f, 0x1a,
	0xf9, 0x3d, 0xbf, 0xd0, 0xfc, 0x92, 0x8f, 0x10, 0xbf, 0xd4, 0x7c, 0xc9, 0x5f, 0x20, 0xbe, 0xd4,
	0xfc, 0x8a, 0xbf, 0x44, 0xfc, 0x4a, 0xf3, 0x15, 0x1f, 0x23, 0xbe, 0x42, 0x9b, 0xc5, 0x10, 0xc7,
	0x9b, 0x35, 0x41, 0xfc, 0xef, 0x66, 0xdd, 0x70, 0x40, 0xfc, 0x46, 0xf3, 0x35, 0x3f, 0x46, 0x7c,
	0xad, 0xf9, 0x86, 0x9f, 0x20, 0xbe, 0x71, 0x7e, 0x9b, 0xcc, 0xaa, 0x1f, 0x53, 0xec, 0x9f, 0xd0,
	0x0f, 0x84, 0x7e, 0x20, 0xf4, 0x03, 0xa1, 0x1f, 0x08, 0xfd, 0x40, 0xe8, 0x07, 0x42, 0x3f, 0x10,
	0xfa, 0x81, 0xd0, 0x0f, 0x84, 0x7e, 0x20, 0xf4, 0x03, 0xa1, 0x1f, 0x08, 0xfd, 0x40, 0xe8, 0x07,
	0x42, 0x3f, 0x68, 0xfd, 0x3f, 0x0d, 0xf6, 0xa6, 0xd5, 0xff, 0x74, 0xd4, 0x00, 0x11, 0x35, 0x40,
	0x44, 0x0d, 0x10, 0x51, 0x03, 0xff, 0x1f, 0x35, 0xfe, 0xea, 0xcb, 0x32, 0x8a, 0xd5, 0xb7, 0x6a,
	0xe7, 0x86, 0x32, 0xf5, 0x42, 0x91, 0xa9, 0x22, 0x3e, 0x54, 0x51, 0x1d, 0x99, 0x22, 0x8c, 0x4b,
	0xf1, 0x21, 0x2f, 0xa4, 0x3c, 0xe8, 0x88, 0x45, 0xa9, 0xbb, 0x1b, 0x35, 0x91, 0xb2, 0xf8, 0x13,
	0x00, 0x00, 0xff, 0xff, 0xa8, 0xec, 0xe5, 0x47, 0x92, 0x05, 0x00, 0x00,
}
