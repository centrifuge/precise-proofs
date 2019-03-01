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

	leaves, err := FlattenMessage(&message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	assert.Equal(t, 9, len(leaves))

	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}

	assert.Equal(t, []Property{
		Empty.FieldProp("ValueCamelCased", 6),
		Empty.FieldProp("enum_type", 10),
		Empty.FieldProp("value1", 3),
		Empty.FieldProp("value2", 4),
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
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
	assert.Equal(t, expectedHash[:], leaves[4].Hash)
}

func TestFlattenMessage_compact(t *testing.T) {
	message := documentspb.ExampleDocument{
		ValueA: "Foo",
	}

	leaves, err := FlattenMessage(&message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, true, false, Empty)
	assert.NoError(t, err)
	assert.Equal(t, 9, len(leaves))

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
	leaves, err := FlattenMessage(&message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, parentProp)
	assert.NoError(t, err)
	assert.Equal(t, 9, len(leaves))

	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}

	assert.Equal(t, []Property{
		parentProp.FieldProp("ValueCamelCased", 6),
		parentProp.FieldProp("enum_type", 10),
		parentProp.FieldProp("value1", 3),
		parentProp.FieldProp("value2", 4),
		parentProp.FieldProp("valueA", 1),
		parentProp.FieldProp("valueB", 2),
		parentProp.FieldProp("value_bytes1", 5),
		parentProp.FieldProp("value_not_hashed", 9),
		parentProp.FieldProp("value_not_ignored", 7),
	}, propOrder)
	f := &messageFlattener{}
	v, _ := f.valueToBytesArray("Foo")

	expectedPayload := append([]byte("doc.valueA"), v...)
	expectedPayload = append(expectedPayload, testSalt[:]...)
	expectedHash := sha256.Sum256(expectedPayload)
	assert.Equal(t, expectedHash[:], leaves[4].Hash)
}

func TestFlattenMessage_AllFieldTypes(t *testing.T) {
	message := documentspb.NewAllFieldTypes()

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	var propOrder []Property
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

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("ValueCamelCased", 6),
		Empty.FieldProp("enum_type", 10),
		Empty.FieldProp("value1", 3),
		Empty.FieldProp("value2", 4),
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("value_bytes1", 5),
		Empty.FieldProp("value_not_hashed", 9),
		Empty.FieldProp("value_not_ignored", 7),
	}, propOrder)
	assert.Nil(t, err)
	assert.Equal(t, leaves[7].Hash, foobarHash[:])
	assert.Equal(t, leaves[7].Value, []byte{})

	invalidMessage := &documentspb.InvalidHashedFieldDocument{
		Value: "foobar",
	}

	leaves, err = FlattenMessage(invalidMessage, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.EqualError(t, err, "The option hashed_field is only supported for type `bytes`")
}

func TestFlattenMessage_Oneof(t *testing.T) {
	message := &documentspb.OneofSample{
		OneofBlock: &documentspb.OneofSample_ValueB{int32(1)},
	}
	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
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
	leaves, err = FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
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
	leaves, err = FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
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

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("value", 1)
	mapElemProp, err := mapProp.MapElemProp(int32(42), 0)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultSaltsLengthSuffix),
		mapElemProp,
	}, propOrder)

}

func TestFlattenMessage_SimpleStringMap(t *testing.T) {
	message := &documentspb.SimpleStringMap{
		Value: map[string]string{
			"key": "value",
		},
	}

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("value", 1)
	mapElemProp, err := mapProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultSaltsLengthSuffix),
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

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	var propOrder []Property
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
		mapProp.LengthProp(DefaultSaltsLengthSuffix),
		mapElemProp.LengthProp(DefaultSaltsLengthSuffix),
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

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("entries", 1)
	mapElemProp, err := mapProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultSaltsLengthSuffix),
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

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("entries", 1)
	mapElemProp, err := mapProp.MapElemProp("key", 32)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultSaltsLengthSuffix),
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

	leaves, err := FlattenMessage(message, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	mapProp := Empty.FieldProp("entries", 1)
	mapElemProp, err := mapProp.MapElemProp([]byte("abcdefghijklmnopqrst"), 20)
	assert.NoError(t, err)
	assert.Equal(t, []Property{
		mapProp.LengthProp(DefaultSaltsLengthSuffix),
		mapElemProp,
	}, propOrder)

}

func TestFlattenMessageFromAutoFillSalts(t *testing.T) {
	exampleFNDoc := &documentspb.ExampleFilledNestedRepeatedDocument

	rootProp := NewProperty("doc", 42)
	leaves, err := FlattenMessage(exampleFNDoc, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, rootProp)
	assert.Nil(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		rootProp.FieldProp("valueA", 1),
		rootProp.FieldProp("valueB", 2),
		rootProp.FieldProp("valueC", 3).LengthProp(DefaultSaltsLengthSuffix),
		rootProp.FieldProp("valueC", 3).SliceElemProp(0).FieldProp("valueA", 1),
		rootProp.FieldProp("valueC", 3).SliceElemProp(1).FieldProp("valueA", 1),
		rootProp.FieldProp("valueD", 4).FieldProp("valueA", 1).FieldProp("valueA", 1),
		rootProp.FieldProp("valueD", 4).FieldProp("valueB", 2),
	}, propOrder)
}

func TestFlattenMessageFromAlreadyFilledSalts(t *testing.T) {
	exampleDoc := &documentspb.ExampleFilledNestedRepeatedDocument
	leaves, err := FlattenMessage(exampleDoc, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.Nil(t, err)
	var propOrder []Property
	for _, leaf := range leaves {
		propOrder = append(propOrder, leaf.Property)
	}
	assert.Equal(t, []Property{
		Empty.FieldProp("valueA", 1),
		Empty.FieldProp("valueB", 2),
		Empty.FieldProp("valueC", 3).LengthProp(DefaultSaltsLengthSuffix),
		Empty.FieldProp("valueC", 3).SliceElemProp(0).FieldProp("valueA", 1),
		Empty.FieldProp("valueC", 3).SliceElemProp(1).FieldProp("valueA", 1),
		Empty.FieldProp("valueD", 4).FieldProp("valueA", 1).FieldProp("valueA", 1),
		Empty.FieldProp("valueD", 4).FieldProp("valueB", 2),
	}, propOrder)
}

func TestDocumentTree_IgnoreExcludeFromTree(t *testing.T) {
	doc := &documentspb.ExampleDocument{
		ValueIgnored: []byte("this is not ignored"),
	}

	leaves, err := FlattenMessage(doc, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, true, Empty)
	assert.NoError(t, err)
	assert.Equal(t, 10, len(leaves))

	leaves, err = FlattenMessage(doc, NewSaltForTest, DefaultSaltsLengthSuffix, sha256Hash, false, false, Empty)
	assert.NoError(t, err)
	assert.Equal(t, 9, len(leaves))
}
