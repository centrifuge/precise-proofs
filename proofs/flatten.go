package proofs

import (
	"hash"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	go_descriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pkg/errors"

	"github.com/centrifuge/precise-proofs/proofs/proto"
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

func (f *messageFlattener) handleValue(prop *Property, value reflect.Value, saltValue reflect.Value, lengthSaltValue reflect.Value, fieldDescriptor *go_descriptor.FieldDescriptorProto) (err error) {
	// handle special cases
	switch v := value.Interface().(type) {
	case []byte, *timestamp.Timestamp:
		valueString, err := f.valueToString(v)
		if err != nil {
			return errors.Wrap(err, "failed convert value to string")
		}
		f.appendLeaf(*prop, valueString, saltValue.Interface().([]byte), []byte{}, false)
		return nil
	}

	// handle generic recursive cases
	switch value.Kind() {
	case reflect.Ptr:
		return f.handleValue(prop, value.Elem(), saltValue.Elem(), reflect.Value{}, fieldDescriptor)
	case reflect.Struct:
		_, messageDescriptor := descriptor.ForMessage(value.Addr().Interface().(descriptor.Message))

		// Handle each field of the struct
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)

			// Ignore fields starting with XXX_, those are protobuf internals
			if strings.HasPrefix(field.Name, "XXX_") {
				continue
			}

			fieldDescriptor := messageDescriptor.Field[i]

			// Check if the field has an exclude_from_tree option and skip it
			excludeFromTree, err := proto.GetExtension(fieldDescriptor.Options, proofspb.E_ExcludeFromTree)
			if err == nil && *(excludeFromTree.(*bool)) {
				continue
			}

			protoTag := field.Tag.Get("protobuf")
			name, num, err := ExtractFieldTags(protoTag)
			if err != nil {
				return errors.Wrapf(err, "failed to extract protobuf tag info from %q", protoTag)
			}

			var fieldProp Property
			if prop == nil {
				fieldProp = NewProperty(name, num)
			} else {
				fieldProp = prop.FieldProp(name, num)
			}

			isHashed, err := proto.GetExtension(fieldDescriptor.Options, proofspb.E_HashedField)
			if err == nil && *(isHashed.(*bool)) {
				// Fields that have the hashed_field tag on the protobuf message will be treated as hashes without prepending
				// the property & salt.
				hash, ok := value.Field(i).Interface().([]byte)
				if !ok {
					return errors.New("The option hashed_field is only supported for type `bytes`")
				}

				f.appendLeaf(fieldProp, "", nil, hash, true)
				continue
			}

			fieldSaltValue := saltValue.FieldByName(field.Name)
			fieldLengthSaltValue := saltValue.FieldByName(field.Name + f.saltsLengthSuffix)
			err = f.handleValue(&fieldProp, value.Field(i), fieldSaltValue, fieldLengthSaltValue, fieldDescriptor)
			if err != nil {
				return errors.Wrapf(err, "error handling field %s", field.Name)
			}
		}
	case reflect.Slice:
		// Append length of slice as tree leaf
		f.appendLeaf(prop.LengthProp(), strconv.Itoa(value.Len()), lengthSaltValue.Interface().([]byte), []byte{}, false)

		// Handle each element of the slice
		for i := 0; i < value.Len(); i++ {
			elemProp := prop.SliceElemProp(FieldNum(i))
			err := f.handleValue(&elemProp, value.Index(i), saltValue.Index(i), reflect.Value{}, nil)
			if err != nil {
				return errors.Wrapf(err, "error handling slice element %d", i)
			}
		}
	case reflect.Map:
		// Append size of map as tree leaf
		f.appendLeaf(prop.LengthProp(), strconv.Itoa(value.Len()), lengthSaltValue.Interface().([]byte), []byte{}, false)

		// Handle each value of the map
		for _, k := range value.MapKeys() {
			extVal, err := proto.GetExtension(fieldDescriptor.Options, proofspb.E_KeyMaxLength)
			if err != nil {
				return errors.Wrap(err, "no key_max_length specified")
			}

			maxLength := *(extVal.(*uint64))

			elemProp, err := prop.MapElemProp(k.Interface(), maxLength)
			if err != nil {
				return errors.Wrapf(err, "failed to create elem prop for %q", k)
			}
			err = f.handleValue(&elemProp, value.MapIndex(k), saltValue.MapIndex(k), reflect.Value{}, nil)
			if err != nil {
				return errors.Wrapf(err, "error handling slice element %s", k)
			}
		}
	default:
		// return errors.Errorf("cannot flatten %s: %s", prop.ReadableName(), value.Kind())
		valueString, err := f.valueToString(value.Interface())
		if err != nil {
			return err
		}
		f.appendLeaf(*prop, valueString, saltValue.Interface().([]byte), []byte{}, false)
	}

	return nil
}

func (f *messageFlattener) appendLeaf(prop Property, value string, salt []byte, hash []byte, hashed bool) {
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
	case int64:
		return strconv.FormatInt(v, 10), nil
	case []byte:
		return f.valueEncoder.EncodeToString(v), nil
	case *timestamp.Timestamp:
		if v == nil {
			return "", nil
		}
		return ptypes.TimestampString(v), nil
	default:
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
func FlattenMessage(message, messageSalts proto.Message, saltsLengthSuffix string, hashFn hash.Hash, valueEncoder ValueEncoder, compact bool, parentProp *Property) (leaves []LeafNode, err error) {
	f := messageFlattener{
		saltsLengthSuffix: saltsLengthSuffix,
		hash:              hashFn,
		valueEncoder:      valueEncoder,
		compactProperties: compact,
	}

	err = f.handleValue(parentProp, reflect.ValueOf(message), reflect.ValueOf(messageSalts), reflect.Value{}, nil)
	if err != nil {
		return
	}

	err = f.sortLeaves()
	if err != nil {
		return []LeafNode{}, err
	}
	return f.leaves, nil
}
