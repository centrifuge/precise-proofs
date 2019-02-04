package proofs

import (
	"fmt"
	"hash"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/centrifuge/precise-proofs/proofs/proto"
	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	go_descriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/protoc-gen-go/generator"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pkg/errors"
)

// messageFlattener takes a proto.Message and flattens it to a list of ordered nodes.
type messageFlattener struct {
	message           proto.Message
	leaves            LeafList
	nodes             [][]byte
	propOrder         []Property
	saltsLengthSuffix string
	hash              hash.Hash
	valueEncoder      ValueEncoder
	compactProperties bool
}

func (f *messageFlattener) handleValue(prop Property, value reflect.Value, getSalt GetSalt, saltsLengthSuffix string, outerFieldDescriptor *go_descriptor.FieldDescriptorProto) (err error) {
	// handle special cases
	switch v := value.Interface().(type) {
	case []byte, *timestamp.Timestamp:
		valueString, err := f.valueToString(v)
		if err != nil {
			return errors.Wrap(err, "failed convert value to string")
		}
		f.appendLeaf(prop, valueString, getSalt(prop.CompactName()), saltsLengthSuffix, nil, false)
		return nil
	}

	// handle generic recursive cases
	switch value.Kind() {
	case reflect.Ptr:
		return f.handleValue(prop, value.Elem(), getSalt, saltsLengthSuffix, outerFieldDescriptor)
	case reflect.Struct:

		// lookup map key from field descriptor, if it exists
		mappingKeyFieldName := generator.CamelCase(getMappingKeyFrom(outerFieldDescriptor))

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

			protoTag := field.Tag.Get("protobuf")
			name, num, err := ExtractFieldTags(protoTag)
			if err != nil {
				return errors.Wrapf(err, "failed to extract protobuf tag info from %q", protoTag)
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

				f.appendLeaf(fieldProp, "", nil, saltsLengthSuffix, hashed, true)
				continue
			}
			if oneOfField {
				err = f.handleValue(fieldProp, value.Field(i).Elem().Elem().Field(0), getSalt, saltsLengthSuffix, innerFieldDescriptor)
			} else {
				err = f.handleValue(fieldProp, value.Field(i), getSalt, saltsLengthSuffix, innerFieldDescriptor)
			}

			if err != nil {
				return errors.Wrapf(err, "error handling field %s", field.Name)
			}
		}
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
			if err != nil {
				return errors.Wrapf(err, "failed to convert %s saltValue to map with mapping_key %q", value.Type(), mappingKey)
			}
			return f.handleValue(prop, mapValue, getSalt, saltsLengthSuffix, outerFieldDescriptor)
		}

		// Append length of slice as tree leaf
		lengthProp := prop.LengthProp(saltsLengthSuffix)
		f.appendLeaf(lengthProp, strconv.Itoa(value.Len()), getSalt(lengthProp.CompactName()), saltsLengthSuffix, []byte{}, false)

		// Handle each element of the slice
		for i := 0; i < value.Len(); i++ {
			elemProp := prop.SliceElemProp(FieldNumForSliceLength(i))
			err := f.handleValue(elemProp, value.Index(i), getSalt, saltsLengthSuffix, nil)
			if err != nil {
				return errors.Wrapf(err, "error handling slice element %d", i)
			}
		}
	case reflect.Map:
		// Append size of map as tree leaf
		lengthProp := prop.LengthProp(saltsLengthSuffix)
		f.appendLeaf(lengthProp, strconv.Itoa(value.Len()), getSalt(lengthProp.CompactName()), saltsLengthSuffix, []byte{}, false)

		// Handle each value of the map
		for _, k := range value.MapKeys() {
			keyLength := getKeyLengthFrom(outerFieldDescriptor)

			elemProp, err := prop.MapElemProp(k.Interface(), keyLength)
			if err != nil {
				return errors.Wrapf(err, "failed to create elem prop for %q", k)
			}
			err = f.handleValue(elemProp, value.MapIndex(k), getSalt, saltsLengthSuffix, outerFieldDescriptor)
			if err != nil {
				return errors.Wrapf(err, "error handling slice element %s", k)
			}
		}
	default:
		valueString, err := f.valueToString(value.Interface())
		if err != nil {
			return err
		}
		f.appendLeaf(prop, valueString, getSalt(prop.CompactName()), saltsLengthSuffix, []byte{}, false)
	}

	return nil
}

func (f *messageFlattener) appendLeaf(prop Property, value string, salt []byte, saltsLengthSuffix string, hash []byte, hashed bool) {
	leaf := LeafNode{
		Property: prop,
		Value:    value,
		Salt:     salt,
		Hash:     hash,
		Hashed:   hashed,
	}
	f.leaves = append(f.leaves, leaf)
}

func (f *messageFlattener) valueToString(value interface{}) (s string, err error) {
	switch v := value.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64:
		return fmt.Sprint(value), nil
	case []byte:
		return f.valueEncoder.EncodeToString(v), nil
	case *timestamp.Timestamp:
		if v == nil {
			return "", nil
		}
		return ptypes.TimestampString(v), nil
	default:
		// special case for enums
		rv := reflect.ValueOf(value)
		if rv.Kind() == reflect.Int32 {
			return strconv.FormatInt(rv.Int(), 10), nil
		}

		return "", errors.Errorf("Got unsupported value of type %T", v)
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
func FlattenMessage(message proto.Message, getSalt GetSalt, saltsLengthSuffix string, hashFn hash.Hash, valueEncoder ValueEncoder, compact bool, parentProp Property) (leaves []LeafNode, err error) {
	f := messageFlattener{
		saltsLengthSuffix: saltsLengthSuffix,
		hash:              hashFn,
		valueEncoder:      valueEncoder,
		compactProperties: compact,
	}

	err = f.handleValue(parentProp, reflect.ValueOf(message), getSalt, saltsLengthSuffix, nil)
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
		extractKeyByteSlice := extractKey
		extractKey = func(v reflect.Value) (reflect.Value, error) {
			bs, _ := extractKeyByteSlice(v)
			if uint64(bs.Len()) != keyLength {
				return reflect.Value{}, errors.Errorf("could not use %x as mapping_key - does not have length %d", bs, keyLength)
			}
			ba := reflect.New(keyType)
			reflect.Copy(ba.Elem(), bs)
			return ba.Elem(), nil
		}
	}
	extractValue := func(v reflect.Value) reflect.Value {
		return v
	}

	_, elemMD := descriptor.ForMessage(reflect.New(elemType).Interface().(descriptor.Message))
	if len(elemMD.Field) == 2 {
		valueField, valueFound := elemType.FieldByNameFunc(func(name string) bool {
			return !strings.HasPrefix(name, "XXX_") && name != mappingKey
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

func getKeyLengthFrom(fd *go_descriptor.FieldDescriptorProto) (keyLength uint64) {
	if fd == nil {
		return
	}

	extVal, err := proto.GetExtension(fd.Options, proofspb.E_KeyLength)
	if err == nil {
		keyLength = *(extVal.(*uint64))
	}

	return
}

func getMappingKeyFrom(fd *go_descriptor.FieldDescriptorProto) (mappingKey string) {
	if fd == nil {
		return
	}

	extVal, err := proto.GetExtension(fd.Options, proofspb.E_MappingKey)
	if err == nil {
		mappingKey = *(extVal.(*string))
	}

	return
}
