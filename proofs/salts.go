package proofs

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"

	"github.com/golang/protobuf/descriptor"
	"github.com/golang/protobuf/proto"
	go_descriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/protoc-gen-go/generator"

	"github.com/centrifuge/precise-proofs/proofs/proto"
)

// FillSalts is a helper message that iterates over all fields in a proto.Message struct and fills them with 32 byte
// random values.
//
// This method will fail if there are any fields of type other than []byte (bytes in protobuf) in the
// message leaf.
//
// The `saltsMessage` protobuf value provided will need to add one extra field for each field that is defined as `repeated`.
//
// The suffix of the slice field needs to end in: `Length` or customized as described above.
func FillSalts(dataMessage, saltsMessage proto.Message) (err error) {
	value := reflect.ValueOf(dataMessage)
	saltValue := reflect.ValueOf(saltsMessage)
	return fillSalts(value, saltValue, nil)
}

func fillSalts(value, saltValue reflect.Value, fieldDescriptor *go_descriptor.FieldDescriptorProto) (err error) {

	if saltValue.Type() == reflect.TypeOf([]byte{}) {
		saltValue.SetBytes(NewSalt())
		return nil
	}

	switch saltValue.Kind() {
	case reflect.Ptr:
		if saltValue.CanSet() {
			saltValue.Set(reflect.New(saltValue.Type().Elem()))
		}
		return fillSalts(value.Elem(), saltValue.Elem(), fieldDescriptor)
	case reflect.Slice:
		return handleFillSaltsSlice(value, saltValue, fieldDescriptor)
	case reflect.Struct:
		return handleFillSaltsStruct(value, saltValue, fieldDescriptor)
	case reflect.Map:
		return handleFillSaltsMap(value, saltValue, fieldDescriptor)
	}

	return fmt.Errorf("Cannot fill %q with salts", saltValue.Type())

}

func handleFillSaltsMap(value, saltValue reflect.Value, fieldDescriptor *go_descriptor.FieldDescriptorProto) (err error) {
	newMap := reflect.MakeMapWithSize(saltValue.Type(), value.Len())
	saltValue.Set(newMap)

	for _, k := range value.MapKeys() {
		valueElem := value.MapIndex(k)
		saltValueElem := reflect.New(saltValue.Type().Elem()).Elem()
		err := fillSalts(valueElem, saltValueElem, fieldDescriptor)
		if err != nil {
			return err
		}
		saltValue.SetMapIndex(k, saltValueElem)
	}
	return
}

func handleFillSaltsSlice(value, saltValue reflect.Value, fieldDescriptor *go_descriptor.FieldDescriptorProto) error {

	newSlice := reflect.MakeSlice(saltValue.Type(), value.Len(), value.Len())
	saltValue.Set(newSlice)

	for i := 0; i < value.Len(); i++ {
		valueElem := value.Index(i)
		saltValueElem := saltValue.Index(i)

		err := fillSalts(valueElem, saltValueElem, fieldDescriptor)
		if err != nil {
			return err
		}
	}
	return nil
}

func handleFillSaltsStruct(value, saltValue reflect.Value, outerFieldDescriptor *go_descriptor.FieldDescriptorProto) (err error) {

    // lookup map key from field descriptor, if it exists
    mappingKeyFieldName := ""
    if outerFieldDescriptor != nil {
        mappingKeyVal, err := proto.GetExtension(outerFieldDescriptor.Options, proofspb.E_MappingKey)
        if err == nil {
            mappingKeyFieldName = generator.CamelCase(*(mappingKeyVal.(*string)))
        }
    }

	_, md := descriptor.ForMessage(value.Addr().Interface().(descriptor.Message))

	for i := 0; i < saltValue.NumField(); i++ {
		saltField := saltValue.Type().Field(i)
		fieldName := saltField.Name

		if strings.HasPrefix(fieldName, "XXX_") {
			continue
		}

		fieldValue := value.FieldByName(fieldName)
		saltFieldValue := saltValue.Field(i)

        if fieldName == mappingKeyFieldName {
            // this is the map key field
            // so instead of filling this field with a salt
            // we copy the field value from value
            saltFieldValue.Set(fieldValue)
            continue
        }

        // get the field descriptor for this field to pass along
		valueField, fieldExistsInValue := value.Type().FieldByName(fieldName)
		var innerFieldDescriptor *go_descriptor.FieldDescriptorProto
		if fieldExistsInValue {
			innerFieldDescriptor = md.Field[valueField.Index[0]]
		}

		err = fillSalts(fieldValue, saltFieldValue, innerFieldDescriptor)
		if err != nil {
			return err
		}
	}
	return
}

// NewSalt creates a 32 byte slice with random data using the crypto/rand RNG
func NewSalt() (salt []byte) {
	randbytes := make([]byte, 32)
	rand.Read(randbytes)
	return randbytes
}
