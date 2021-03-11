package proofs

import (
	"bytes"
	"encoding/binary"
	"hash"
	"reflect"
	"sort"
	"strings"

	proofspb "github.com/centrifuge/precise-proofs/proofs/proto"
	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	godescriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/protoc-gen-go/generator"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pkg/errors"
)

// messageFlattener takes a proto.Message and flattens it to a list of ordered nodes.
type messageFlattener struct {
	message                      proto.Message
	leaves                       LeafList
	nodes                        [][]byte
	propOrder                    []Property
	readablePropertyLengthSuffix string
	hash                         hash.Hash
	compactProperties            bool
	fixedLengthFieldLeftPadding  bool
}

func (f *messageFlattener) handleValue(prop Property, value reflect.Value, salts Salts, readablePropertyLengthSuffix string, outerFieldDescriptor *godescriptor.FieldDescriptorProto, skipSalts bool) (err error) {
	// handle special cases
	// if the underlying value is nil, let's skip it
	if !value.IsValid() {
		return nil
	}

	// Check if we should skip salts from now on
	skipSalts = skipSalts || getNoSaltFrom(outerFieldDescriptor)

	switch v := value.Interface().(type) {
	case []byte, *timestamp.Timestamp:
		var valueBytesArray []byte
		var err error
		if outerFieldDescriptor != nil {
			var extVal interface{}
			extVal, err = proto.GetExtension(outerFieldDescriptor.Options, proofspb.E_FieldLength)
			if err == nil {
				fixedFieldLength := *(extVal.(*uint64))
				valueBytesArray, err = f.valueToPaddingBytesArray(v, int(fixedFieldLength))
			} else {
				valueBytesArray, err = f.valueToBytesArray(v)
			}
		} else {
			valueBytesArray, err = f.valueToBytesArray(v)
		}
		if err != nil {
			return err
		}
		salt, err := salts(prop.CompactName())
		if err != nil {
			return err
		}
		f.appendLeaf(prop, valueBytesArray, salt, readablePropertyLengthSuffix, nil, false)
		return nil
	}

	// handle generic recursive cases
	switch value.Kind() {
	case reflect.Ptr:
		return f.handleValue(prop, value.Elem(), salts, readablePropertyLengthSuffix, outerFieldDescriptor, skipSalts)
	case reflect.Struct:

		// lookup map key from field descriptor, if it exists
		mappingKeyFieldName := generator.CamelCase(getMappingKeyFrom(outerFieldDescriptor))

		// get append fields extension
		appendFields := getAppendFieldsFrom(outerFieldDescriptor)
		fieldMap := make(map[uint32][]byte)

		_, messageDescriptor := descriptor.ForMessage(value.Addr().Interface().(descriptor.Message))

		// Handle each field of the struct
		for i := 0; i < value.NumField(); i++ {
			oneOfField := false
			field := value.Type().Field(i)
			if field.Tag.Get("protobuf_oneof") != "" {
				if value.Field(i).IsNil() {
					continue
				}
				field = value.Field(i).Elem().Elem().Type().Field(0)
				oneOfField = true
			}
			// Ignore fields starting with XXX_, those are protobuf internals
			if strings.HasPrefix(field.Name, "XXX_") {
				continue
			}

			if field.Name == mappingKeyFieldName {
				// this is the map key field
				// so we skip flattening this field
				continue
			}

			innerFieldDescriptor := messageDescriptor.Field[i]

			// Check if the field has an exclude_from_tree option and skip it
			excludeFromTree, err := proto.GetExtension(innerFieldDescriptor.Options, proofspb.E_ExcludeFromTree)
			if err == nil && *(excludeFromTree.(*bool)) {
				continue
			}

			fixedLength := getKeyLengthFrom(innerFieldDescriptor)
			protoTag := field.Tag.Get("protobuf")
			name, num, err := ExtractFieldTags(protoTag)
			if err != nil {
				return errors.Wrapf(err, "failed to extract protobuf tag info from %q", protoTag)
			}

			// if field's name is salts, then bypass flatten this node because it just contain salts
			if name == "salts" {
				if strings.Contains(protoTag, ",rep,") {
					continue
				}
			}
			fieldProp := prop.FieldProp(name, num)

			isHashed, err := proto.GetExtension(innerFieldDescriptor.Options, proofspb.E_HashedField)
			if err == nil && *(isHashed.(*bool)) {
				// Fields that have the hashed_field tag on the protobuf message will be treated as hashes without prepending
				// the property & salt.
				hashed, ok := value.Field(i).Interface().([]byte)
				if oneOfField {
					hashed, ok = value.Field(i).Elem().Elem().Field(0).Interface().([]byte)
				}
				if !ok {
					return errors.New("The option hashed_field is only supported for type `bytes`")
				}

				// if append fields, add it to the fields
				if appendFields {
					fieldMap[uint32(num)] = hashed
					continue
				}

				f.appendLeaf(fieldProp, []byte{}, nil, readablePropertyLengthSuffix, hashed, true)
				continue
			}

			var nextValue reflect.Value
			if oneOfField {
				nextValue = value.Field(i).Elem().Elem().Field(0)
			} else {
				nextValue = value.Field(i)
			}

			// if append fields are enabled, check if we can append the field
			if appendFields {
				var b []byte
				if fixedLength == 0 {
					b, err = f.valueToBytesArray(nextValue.Interface())
				} else {
					b, err = f.valueToPaddingBytesArray(nextValue.Interface(), int(fixedLength))
				}
				if err != nil {
					return errors.Wrapf(err, "failed to append the field %s", field.Name)
				}

				fieldMap[uint32(num)] = b
				continue
			}

			err = f.handleValue(fieldProp, nextValue, salts, readablePropertyLengthSuffix, innerFieldDescriptor, skipSalts)
			if err != nil {
				return errors.Wrapf(err, "error handling field %s", field.Name)
			}
		}

		if !appendFields {
			return nil
		}

		// if append fields enabled, sort and add the field
		var keys []int
		for k := range fieldMap {
			keys = append(keys, int(k))
		}

		sort.Ints(keys)
		var finalValue []byte
		for _, k := range keys {
			finalValue = append(finalValue, fieldMap[uint32(k)]...)
		}

		var salt []byte
		if !skipSalts {
			salt, err = salts(prop.CompactName())
			if err != nil {
				return err
			}
		}

		f.appendLeaf(prop, finalValue, salt, readablePropertyLengthSuffix, nil, false)

	case reflect.Slice:
		mappingKey := generator.CamelCase(getMappingKeyFrom(outerFieldDescriptor))
		if mappingKey != "" {
			keyLength := getKeyLengthFrom(outerFieldDescriptor)
			// a mapping key was defined for this repeated field
			// convert it to a map, and then handle this value as
			// a map instead of a slice
			mapValue, err := sliceToMap(value, mappingKey, keyLength)
			if err != nil {
				return errors.Wrapf(err, "failed to convert %s value to map with mapping_key %q", value.Type(), mappingKey)
			}
			return f.handleValue(prop, mapValue, salts, readablePropertyLengthSuffix, outerFieldDescriptor, skipSalts)
		}

		// Append length of slice as tree leaf
		lengthProp := prop.LengthProp(readablePropertyLengthSuffix)
		lengthBytes, err := toBytesArray(value.Len())
		if err != nil {
			return err
		}
		salt, err := salts(lengthProp.CompactName())
		if err != nil {
			return err
		}
		f.appendLeaf(lengthProp, lengthBytes, salt, readablePropertyLengthSuffix, []byte{}, false)

		// Handle each element of the slice
		for i := 0; i < value.Len(); i++ {
			elemProp := prop.SliceElemProp(FieldNumForSliceLength(i))
			err := f.handleValue(elemProp, value.Index(i), salts, readablePropertyLengthSuffix, outerFieldDescriptor, skipSalts)
			if err != nil {
				return errors.Wrapf(err, "error handling slice element %d", i)
			}
		}
	case reflect.Map:
		// Append size of map as tree leaf
		lengthProp := prop.LengthProp(readablePropertyLengthSuffix)
		lengthBytes, err := toBytesArray(value.Len())
		if err != nil {
			return err
		}
		salt, err := salts(lengthProp.CompactName())
		if err != nil {
			return err
		}
		f.appendLeaf(lengthProp, lengthBytes, salt, readablePropertyLengthSuffix, []byte{}, false)

		// Handle each value of the map
		for _, k := range value.MapKeys() {
			keyLength := getKeyLengthFrom(outerFieldDescriptor)
			if keyLength == 0 {
				keyLength = fetchLengthFromInterface(k)
			}
			elemProp, err := prop.MapElemProp(k.Interface(), keyLength)
			if err != nil {
				return errors.Wrapf(err, "failed to create elem prop for %q", k)
			}
			err = f.handleValue(elemProp, value.MapIndex(k), salts, readablePropertyLengthSuffix, outerFieldDescriptor, skipSalts)
			if err != nil {
				return errors.Wrapf(err, "error handling slice element %s", k)
			}
		}
	default:
		var valueBytesArray []byte
		var err error
		// Check if the field has an padded_field_length option
		if outerFieldDescriptor != nil {
			var extVal interface{}
			extVal, err = proto.GetExtension(outerFieldDescriptor.Options, proofspb.E_FieldLength)
			if err == nil {
				fixedFieldLength := *(extVal.(*uint64))
				valueBytesArray, err = f.valueToPaddingBytesArray(value.Interface(), int(fixedFieldLength))
			} else {
				valueBytesArray, err = f.valueToBytesArray(value.Interface())
			}
		} else {
			valueBytesArray, err = f.valueToBytesArray(value.Interface())
		}
		if err != nil {
			return err
		}
		var salt []byte
		if !skipSalts {
			salt, err = salts(prop.CompactName())
			if err != nil {
				return err
			}
		}
		f.appendLeaf(prop, valueBytesArray, salt, readablePropertyLengthSuffix, []byte{}, false)
	}

	return nil
}

func fetchLengthFromInterface(k reflect.Value) uint64 {
	switch k.Kind() {
	case reflect.Interface:
		v := reflect.ValueOf(k.Interface())
		return fetchLengthFromInterface(v)
	case reflect.Array, reflect.Slice, reflect.String, reflect.Chan, reflect.Map:
		return uint64(k.Len())
	}

	return 0
}

func (f *messageFlattener) appendLeaf(prop Property, value []byte, salt []byte, readablePropertyLengthSuffix string, hash []byte, hashed bool) {
	leaf := LeafNode{
		Property: prop,
		Value:    value,
		Salt:     salt,
		Hash:     hash,
		Hashed:   hashed,
	}
	f.leaves = append(f.leaves, leaf)
}

func (f *messageFlattener) valueToBytesArray(value interface{}) (b []byte, err error) {
	switch v := value.(type) {
	case nil:
		return []byte{}, nil
	case string:
		return []byte(v), nil
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64:
		return toBytesArray(v)
	case []byte:
		return v, nil
	case *timestamp.Timestamp:
		if v == nil {
			return []byte{}, nil
		}

		// Validate `Timestamp`, if valid convert to `Time`
		t, err := ptypes.Timestamp(v)
		if err != nil {
			return []byte{}, nil
		}

		return toBytesArray(t.Unix())
	case bool:
		return toBytesArray(v)
	default:
		// special case for enums
		rv := reflect.ValueOf(value)
		if rv.Kind() == reflect.Int32 {
			return toBytesArray(rv.Int())
		}

		return []byte{}, errors.Errorf("Got unsupported value of type %T", v)
	}
}

func (f *messageFlattener) valueToPaddingBytesArray(value interface{}, fixedLength int) (b []byte, err error) {
	var values []byte
	switch v := value.(type) {
	case string:
		values = []byte(v)
	case []byte:
		values = v
	default:
		return []byte{}, errors.Errorf("Type %T does not surporting padding", v)
	}
	if len(values) > fixedLength {
		return []byte{}, errors.Errorf("Field's length %d is bigger than %d", len(values), fixedLength)
	}
	paddingLength := fixedLength - len(values)
	padding := bytes.Repeat([]byte{0}, paddingLength)
	if f.fixedLengthFieldLeftPadding {
		return append(padding, values...), nil
	} else {
		return append(values, padding...), nil
	}
}

// sortLeaves by the property attribute and copies the properties and
// concatenated byte values into the nodes
func (f *messageFlattener) sortLeaves() (err error) {
	if f.compactProperties {
		sort.Sort(sortByCompactName{f.leaves})
	} else {
		sort.Sort(sortByReadableName{f.leaves})
	}
	f.nodes = make([][]byte, f.leaves.Len())
	f.propOrder = make([]Property, f.leaves.Len())

	for i := 0; i < f.leaves.Len(); i++ {
		leaf := &f.leaves[i]
		if len(leaf.Hash) == 0 && !leaf.Hashed {
			err = leaf.HashNode(f.hash, f.compactProperties)
			if err != nil {
				return err
			}
		}
		f.nodes[i] = leaf.Hash
		f.propOrder[i] = f.leaves[i].Property
	}
	return nil
}

// FlattenMessage takes a protobuf message struct and flattens it into an array
// of nodes.
//
// The fields are sorted lexicographically by their protobuf field names.
func FlattenMessage(message proto.Message, salts Salts, readablePropertyLengthSuffix string, hashFn hash.Hash, compact bool, parentProp Property, fixedLengthFieldLeftPadding bool) (leaves []LeafNode, err error) {
	f := messageFlattener{
		readablePropertyLengthSuffix: readablePropertyLengthSuffix,
		hash:                         hashFn,
		compactProperties:            compact,
		fixedLengthFieldLeftPadding:  fixedLengthFieldLeftPadding,
	}

	err = f.handleValue(parentProp, reflect.ValueOf(message), salts, readablePropertyLengthSuffix, nil, false)
	if err != nil {
		return
	}

	err = f.sortLeaves()
	if err != nil {
		return []LeafNode{}, err
	}
	return f.leaves, nil
}

func sliceToMap(value reflect.Value, mappingKey string, keyLength uint64) (reflect.Value, error) {
	elemType := value.Type().Elem().Elem()
	keyField, keyFound := elemType.FieldByName(mappingKey)
	if !keyFound {
		return reflect.Value{}, errors.Errorf("%s does not have field %q", elemType, mappingKey)
	}
	keyType := keyField.Type
	extractKey := func(v reflect.Value) (reflect.Value, error) {
		return v.Elem().FieldByIndex(keyField.Index), nil
	}
	if keyType == reflect.TypeOf([]byte(nil)) {
		// Go does not allow slices to be the keys of a map
		// but it does allow arrays to be keys
		// since we know the key length, we convert each
		// []byte to [keyLength]byte before using it as a key
		keyType = reflect.ArrayOf(int(keyLength), reflect.TypeOf(byte(0)))

		// if key length is 0
		// then we set the map type as interface{}
		// individual key type will b declared based on the length of each value
		if keyLength == 0 {
			m := make(map[interface{}]bool)
			r := reflect.TypeOf(m)
			keyType = r.Key()
		}

		extractKeyByteSlice := extractKey
		extractKey = func(v reflect.Value) (reflect.Value, error) {
			bs, _ := extractKeyByteSlice(v)
			// if key length is not set or 0,
			// then take the key length of key
			kt := keyType
			if keyLength == 0 {
				kt = reflect.ArrayOf(int(uint64(bs.Len())), reflect.TypeOf(byte(0)))
			}

			if keyLength != 0 && uint64(bs.Len()) != keyLength {
				return reflect.Value{}, errors.Errorf("could not use %x as mapping_key - does not have length %d", bs, keyLength)
			}

			ba := reflect.New(kt)
			reflect.Copy(ba.Elem(), bs)
			return ba.Elem(), nil
		}
	}
	extractValue := func(v reflect.Value) reflect.Value {
		return v
	}

	_, elemMD := descriptor.ForMessage(reflect.New(elemType).Interface().(descriptor.Message))
	_, saltsFieldFound := elemType.FieldByName(SaltsFieldName)
	if (len(elemMD.Field) == 2) || ((len(elemMD.Field) == 3) && (saltsFieldFound)) {
		valueField, valueFound := elemType.FieldByNameFunc(func(name string) bool {
			if saltsFieldFound {
				return !strings.HasPrefix(name, "XXX_") && name != mappingKey && name != SaltsFieldName
			} else {
				return !strings.HasPrefix(name, "XXX_") && name != mappingKey
			}
		})
		if !valueFound {
			return reflect.Value{}, errors.Errorf("could not find field in %s not called %q", elemType, mappingKey)
		}
		extractValue = func(v reflect.Value) reflect.Value {
			return v.Elem().FieldByName(valueField.Name)
		}
		elemType = valueField.Type
	} else {
		elemType = reflect.PtrTo(elemType)
	}

	mapType := reflect.MapOf(keyType, elemType)
	mapValue := reflect.MakeMap(mapType)
	for i := 0; i < value.Len(); i++ {
		key, err := extractKey(value.Index(i))
		if err != nil {
			return reflect.Value{}, err
		}
		value := extractValue(value.Index(i))
		mapValue.SetMapIndex(key, value)
	}
	return mapValue, nil
}

func getKeyLengthFrom(fd *godescriptor.FieldDescriptorProto) (keyLength uint64) {
	if fd == nil {
		return
	}

	extVal, err := proto.GetExtension(fd.Options, proofspb.E_FieldLength)
	if err == nil {
		keyLength = *(extVal.(*uint64))
	}

	return
}

func getMappingKeyFrom(fd *godescriptor.FieldDescriptorProto) (mappingKey string) {
	if fd == nil {
		return
	}

	extVal, err := proto.GetExtension(fd.Options, proofspb.E_MappingKey)
	if err == nil {
		mappingKey = *(extVal.(*string))
	}

	return
}

func getAppendFieldsFrom(fd *godescriptor.FieldDescriptorProto) bool {
	if fd == nil {
		return false
	}

	extVal, err := proto.GetExtension(fd.Options, proofspb.E_AppendFields)
	if err == nil {
		return *extVal.(*bool)
	}

	return false
}

func getNoSaltFrom(fd *godescriptor.FieldDescriptorProto) bool {
	if fd == nil {
		return false
	}

	extVal, err := proto.GetExtension(fd.Options, proofspb.E_NoSalt)
	if err == nil {
		return *extVal.(*bool)
	}

	return false
}

// Utility function to convert data to `[]byte` representation using BigEndian encoding
func toBytesArray(data interface{}) ([]byte, error) {
	v := reflect.ValueOf(data)
	switch v.Kind() {
	case reflect.Int:
		// binary write doesn't support int
		// as a special case, convert it into int64
		// since the max value of int is int64, we shouldn't lose any data
		data = v.Int()
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, data)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
