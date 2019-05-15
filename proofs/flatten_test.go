package proofs

import (
	"crypto/sha256"
	"testing"

	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/stretchr/testify/assert"
)

func TestFlattenMessage(t *testing.T) {
	message := documentspb.ExampleDocument{
		ValueA: "Foo",
	}

	leaves, err := FlattenMessage(&message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	assert.Equal(t, 12, len(leaves))

	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}

	assert.Equal(t, []Property{
		Empty.FieldProp("ValueCamelCased", 6),
		Empty.FieldProp("enum_type", 10),
		Empty.FieldProp("paddingA", 14),
		Empty.FieldProp("paddingB", 15),
		Empty.FieldProp("value1", 3),
		Empty.FieldProp("value2", 4),
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("valueBool", 12),
		Empty.FieldProp("value_bytes1", 5),
		Empty.FieldProp("value_not_hashed", 9),
		Empty.FieldProp("value_not_ignored", 7),
	}, propOrder)

	f := &messageFlattener{}
	v, err := f.valueToBytesArray("Foo")
	assert.NoError(t, err)

	expectedPayload := append([]byte("valueA"), v...)
	expectedPayload = append(expectedPayload, testSalt[:]...)
	expectedHash := sha256.Sum256(expectedPayload)
	assert.Equal(t, expectedHash[:], leaves[6].Hash)
}

func TestFlattenMessage_compact(t *testing.T) {
	message := documentspb.ExampleDocument{
		ValueA: "Foo",
	}

	leaves, err := FlattenMessage(&message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, true, Empty, false)
	assert.NoError(t, err)
	assert.Equal(t, 12, len(leaves))

	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("value1", 3),
		Empty.FieldProp("value2", 4),
		Empty.FieldProp("value_bytes1", 5),
		Empty.FieldProp("ValueCamelCased", 6),
		Empty.FieldProp("value_not_ignored", 7),
		Empty.FieldProp("value_not_hashed", 9),
		Empty.FieldProp("enum_type", 10),
		Empty.FieldProp("valueBool", 12),
		Empty.FieldProp("paddingA", 14),
		Empty.FieldProp("paddingB", 15),
	}, propOrder)
	f := &messageFlattener{}
	v, _ := f.valueToBytesArray("Foo")

	expectedPayload := append([]byte{0, 0, 0, 1}, v...)
	expectedPayload = append(expectedPayload, testSalt[:]...)
	expectedHash := sha256.Sum256(expectedPayload)
	assert.Equal(t, expectedHash[:], leaves[0].Hash)
}

func TestFlattenMessageWithPrefix(t *testing.T) {
	message := documentspb.ExampleDocument{
		ValueA: "Foo",
	}

	parentProp := NewProperty("doc", 42)
	leaves, err := FlattenMessage(&message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, parentProp, false)
	assert.NoError(t, err)
	assert.Equal(t, 12, len(leaves))

	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}

	assert.Equal(t, []Property{
		parentProp.FieldProp("ValueCamelCased", 6),
		parentProp.FieldProp("enum_type", 10),
		parentProp.FieldProp("paddingA", 14),
		parentProp.FieldProp("paddingB", 15),
		parentProp.FieldProp("value1", 3),
		parentProp.FieldProp("value2", 4),
		parentProp.FieldProp("valueA", 1),
		parentProp.FieldProp("valueB", 2),
		parentProp.FieldProp("valueBool", 12),
		parentProp.FieldProp("value_bytes1", 5),
		parentProp.FieldProp("value_not_hashed", 9),
		parentProp.FieldProp("value_not_ignored", 7),
	}, propOrder)
	f := &messageFlattener{}
	v, _ := f.valueToBytesArray("Foo")

	expectedPayload := append([]byte("doc.valueA"), v...)
	expectedPayload = append(expectedPayload, testSalt[:]...)
	expectedHash := sha256.Sum256(expectedPayload)
	assert.Equal(t, expectedHash[:], leaves[6].Hash)
}

func TestFlattenMessage_AllFieldTypes(t *testing.T) {
	message := documentspb.NewAllFieldTypes()

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("string_value", 1),
		Empty.FieldProp("time_stamp_value", 2),
	}, propOrder)
	assert.Nil(t, err)

}

func TestFlattenMessage_HashedField(t *testing.T) {
	foobarHash := sha256.Sum256([]byte("foobar"))
	message := &documentspb.ExampleDocument{
		ValueA:         "foobar",
		ValueNotHashed: foobarHash[:],
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("ValueCamelCased", 6),
		Empty.FieldProp("enum_type", 10),
		Empty.FieldProp("paddingA", 14),
		Empty.FieldProp("paddingB", 15),
		Empty.FieldProp("value1", 3),
		Empty.FieldProp("value2", 4),
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("valueBool", 12),
		Empty.FieldProp("value_bytes1", 5),
		Empty.FieldProp("value_not_hashed", 9),
		Empty.FieldProp("value_not_ignored", 7),
	}, propOrder)
	assert.Nil(t, err)
	assert.Equal(t, leaves[10].Hash, foobarHash[:])
	assert.Equal(t, leaves[10].Value, []byte{})

	invalidMessage := &documentspb.InvalidHashedFieldDocument{
		Value: "foobar",
	}

	leaves, err = FlattenMessage(invalidMessage, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.EqualError(t, err, "The option hashed_field is only supported for type `bytes`")
}

func TestFlattenMessage_Oneof(t *testing.T) {
	message := &documentspb.OneofSample{
		OneofBlock: &documentspb.OneofSample_ValueB{int32(1)},
	}
	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("valueE", 5),
	}, propOrder)

	assert.Nil(t, err)

	propOrder = []Property{}
	message.OneofBlock = &documentspb.OneofSample_ValueC{"test"}
	leaves, err = FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueC", 3),
		Empty.FieldProp("valueE", 5),
	}, propOrder)
	assert.Nil(t, err)

	propOrder = []Property{}
	message.OneofBlock = &documentspb.OneofSample_ValueD{&documentspb.SimpleItem{ValueA: "testValA"}}
	leaves, err = FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mp := Empty.FieldProp("valueD", 4)
	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		mp.FieldProp("valueA", 1),
		Empty.FieldProp("valueE", 5),
	}, propOrder)
	assert.Nil(t, err)
}

func TestFlattenMessage_SimpleMap(t *testing.T) {
	message := &documentspb.SimpleMap{
		Value: map[int32]string{
			42: "value",
		},
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("value", 1)
	mapElemProp, err := mapProp.MapElemProp(int32(42), 0)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultReadablePropertyLengthSuffix),
		mapElemProp,
	}, propOrder)

}

func TestFlattenMessage_SimpleStringMap(t *testing.T) {
	message := &documentspb.SimpleStringMap{
		Value: map[string]string{
			"key": "value",
		},
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("value", 1)
	mapElemProp, err := mapProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultReadablePropertyLengthSuffix),
		mapElemProp,
	}, propOrder)

}

func TestFlattenMessage_NestedMap(t *testing.T) {
	message := &documentspb.NestedMap{
		Value: map[int32]*documentspb.SimpleMap{
			42: {
				Value: map[int32]string{
					-42: "value",
				},
			},
		},
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("value", 1)
	mapElemProp, err := mapProp.MapElemProp(int32(42), 0)
	assert.NoError(t, err)
	mapElemProp = mapElemProp.FieldProp("value", 1)
	mapElemElemProp, err := mapElemProp.MapElemProp(int32(-42), 0)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultReadablePropertyLengthSuffix),
		mapElemProp.LengthProp(DefaultReadablePropertyLengthSuffix),
		mapElemElemProp,
	}, propOrder)

}

func TestFlattenMessage_SimpleEntries(t *testing.T) {
	message := &documentspb.SimpleEntries{
		Entries: []*documentspb.SimpleEntry{
			{
				EntryKey:   "key",
				EntryValue: "value",
			},
		},
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("entries", 1)
	mapElemProp, err := mapProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultReadablePropertyLengthSuffix),
		mapElemProp,
	}, propOrder)

}

func TestFlattenMessage_Entries(t *testing.T) {
	message := &documentspb.Entries{
		Entries: []*documentspb.Entry{
			{
				EntryKey: "key",
				ValueA:   "valueA",
				ValueB:   []byte("valueB"),
				ValueC:   42,
			},
		},
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("entries", 1)
	mapElemProp, err := mapProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultReadablePropertyLengthSuffix),
		mapElemProp.FieldProp("valueA", 2),
		mapElemProp.FieldProp("valueB", 3),
		mapElemProp.FieldProp("valueC", 4),
	}, propOrder)

}

func TestFlattenMessage_BytesKeyEntries(t *testing.T) {
	message := &documentspb.BytesKeyEntries{
		Entries: []*documentspb.BytesKeyEntry{
			{
				Address: []byte("abcdefghijklmnopqrst"),
				Value:   "value",
			},
		},
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.NoError(t, err)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("entries", 1)
	mapElemProp, err := mapProp.MapElemProp([]byte("abcdefghijklmnopqrst"), 20)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultReadablePropertyLengthSuffix),
		mapElemProp,
	}, propOrder)

}

func TestFlattenMessageFromAutoFillSalts(t *testing.T) {
	exampleFNDoc := &documentspb.ExampleFilledNestedRepeatedDocument

	rootProp := NewProperty("doc", 42)
	leaves, err := FlattenMessage(exampleFNDoc, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, rootProp, false)
	assert.Nil(t, err)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		rootProp.FieldProp("valueA", 1),
		rootProp.FieldProp("valueB", 2),
		rootProp.FieldProp("valueC", 3).LengthProp(DefaultReadablePropertyLengthSuffix),
		rootProp.FieldProp("valueC", 3).SliceElemProp(0).FieldProp("valueA", 1),
		rootProp.FieldProp("valueC", 3).SliceElemProp(1).FieldProp("valueA", 1),
		rootProp.FieldProp("valueD", 4).FieldProp("valueA", 1).FieldProp("valueA", 1),
		rootProp.FieldProp("valueD", 4).FieldProp("valueB", 2),
	}, propOrder)
}

func TestFlattenMessageFromAlreadyFilledSalts(t *testing.T) {
	exampleDoc := &documentspb.ExampleFilledNestedRepeatedDocument
	leaves, err := FlattenMessage(exampleDoc, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.Nil(t, err)
	propOrder := []Property{}
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("valueC", 3).LengthProp(DefaultReadablePropertyLengthSuffix),
		Empty.FieldProp("valueC", 3).SliceElemProp(0).FieldProp("valueA", 1),
		Empty.FieldProp("valueC", 3).SliceElemProp(1).FieldProp("valueA", 1),
		Empty.FieldProp("valueD", 4).FieldProp("valueA", 1).FieldProp("valueA", 1),
		Empty.FieldProp("valueD", 4).FieldProp("valueB", 2),
	}, propOrder)
}

func TestFlatten_AppendFields(t *testing.T) {
	doc := &documentspb.AppendFieldDocument{
		Name: &documentspb.Name{
			First: "bob",
			Last:  "barker",
		},

		Names: []*documentspb.Name{
			{
				First: "john",
				Last:  "doe",
			},

			{
				First: "alice",
				Last:  "adelmann",
			},
		},

		PhoneNumbers: []*documentspb.PhoneNumber{
			{
				Type:        "home",
				Countrycode: "+1",
				Number:      "123456789",
			},
		},
	}

	leaves, err := FlattenMessage(doc, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.Nil(t, err)
	assert.Len(t, leaves, 6)
	assert.Equal(t, leaves[0].Property.ReadableName(), "name")
	assert.Equal(t, leaves[0].Value, []byte("bobbarker"))
	assert.Equal(t, leaves[1].Property.ReadableName(), "names.length")
	assert.Equal(t, leaves[2].Property.ReadableName(), "names[0]")
	assert.Equal(t, leaves[2].Value, []byte("johndoe"))
	assert.Equal(t, leaves[3].Property.ReadableName(), "names[1]")
	assert.Equal(t, leaves[3].Value, []byte("aliceadelmann"))
	assert.Equal(t, leaves[4].Property.ReadableName(), "phone_numbers.length")
	assert.Equal(t, leaves[5].Property.ReadableName(), "phone_numbers[home]")
	assert.Equal(t, leaves[5].Value, []byte("+1123456789"))
	assert.NotNil(t, leaves[5].Salt)
}

func TestFlatten_FieldNoSalt(t *testing.T) {
	doc := &documentspb.NoSaltDocument{
		ValueNoSalt: "ValueNoSalt",
		ValueSalt:   "ValueSalt",
		Name:				 &documentspb.Name{
			First: "john",
			Last: "doe",
		},
	}
	leaves, err := FlattenMessage(doc, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.Nil(t, err)
	assert.Len(t, leaves, 4)
	assert.Equal(t, leaves[2].Property.ReadableName(), "valueNoSalt")
	assert.Equal(t, leaves[2].Value, []byte("ValueNoSalt"))
	assert.Nil(t, leaves[2].Salt)
	assert.Equal(t, leaves[3].Property.ReadableName(), "valueSalt")
	assert.Equal(t, leaves[3].Value, []byte("ValueSalt"))
	assert.NotNil(t, leaves[3].Salt)

	// Check nested message doesn't have salts
	assert.Equal(t, leaves[0].Property.ReadableName(), "name.first")
	assert.Equal(t, leaves[0].Value, []byte("john"))
	assert.Nil(t, leaves[0].Salt)
	assert.Equal(t, leaves[1].Property.ReadableName(), "name.last")
	assert.Equal(t, leaves[1].Value, []byte("doe"))
	assert.Nil(t, leaves[1].Salt)
}

func TestFlatten_AppendField_Failure(t *testing.T) {
	doc := &documentspb.UnsupportedAppendDocument{
		Name: &documentspb.Name{
			First: "hello, ",
			Last:  "World",
		},
		Nested: &documentspb.ExampleNested{
			HashedValue: []byte("some hashed value"),
			Name: &documentspb.Name{
				First: "hello, ",
				Last:  "World",
			},
		},
	}

	_, err := FlattenMessage(doc, NewSaltForTest, DefaultReadablePropertyLengthSuffix, sha256Hash, false, Empty, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Got unsupported value of type *documentspb.Name")
}
