package proofs

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/golang/protobuf/proto"
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
	dataMessageValue := reflect.Indirect(reflect.ValueOf(dataMessage))
	saltsMessageValue := reflect.Indirect(reflect.ValueOf(saltsMessage))

	for i := 0; i < saltsMessageValue.NumField(); i++ {
		saltsField := saltsMessageValue.Field(i)
		saltsType := saltsField.Type()
		valueField := dataMessageValue.FieldByName(saltsMessageValue.Type().Field(i).Name)

		if saltsType.Kind() == reflect.Ptr {
			saltsType = saltsType.Elem()
		}

		if strings.HasPrefix(saltsMessageValue.Type().Field(i).Name, "XXX_") {
			continue
		}

		if saltsType == reflect.TypeOf([]uint8{}) {
			err = handleFillSaltsValue(saltsField)
		} else if saltsType.Kind() == reflect.Slice {
			err = handleFillSaltsSlice(saltsType, saltsField, valueField)
		} else if saltsType.Kind() == reflect.Struct {
			err = handleFillSaltsStruct(saltsField, saltsType, valueField)
		} else {
			return fmt.Errorf("Invalid type (%s) for field (%s)", reflect.TypeOf(saltsField.Interface()).String(), saltsMessageValue.Type().Field(i).Name)
		}

		if err != nil {
			return
		}

	}

	return
}

func handleFillSaltsSlice(saltsType reflect.Type, saltsField reflect.Value, valueField reflect.Value) (err error) {
	if saltsType.Kind() != reflect.Slice || reflect.TypeOf(valueField.Interface()).Kind() != reflect.Slice {
		return fmt.Errorf("Invalid type (%s) or (%s) for field", saltsType.String(), reflect.TypeOf(valueField.Interface()).String())
	}

	sliceType := reflect.SliceOf(saltsType.Elem())
	newSlice := reflect.MakeSlice(sliceType, valueField.Len(), valueField.Len())
	saltsField.Set(newSlice)

	for j := 0; j < valueField.Len(); j++ {
		dataFieldItem := valueField.Index(j)
		saltsFieldItem := saltsField.Index(j)
		saltsFieldItemType := reflect.TypeOf(saltsFieldItem.Interface())
		saltsFieldItem.Set(reflect.Indirect(reflect.New(saltsFieldItemType)))

		var checkType reflect.Type
		if reflect.TypeOf(saltsFieldItem.Interface()).Kind() == reflect.Ptr {
			checkType = reflect.TypeOf(saltsFieldItem.Interface()).Elem()
		} else {
			checkType = reflect.TypeOf(saltsFieldItem.Interface())
		}

		if checkType.Kind() == reflect.Struct {
			err = handleFillSaltsStruct(saltsFieldItem, checkType, dataFieldItem)
		} else {
			err = handleFillSaltsValue(reflect.Indirect(saltsFieldItem))
		}

		if err != nil {
			return
		}
	}
	return
}

func handleFillSaltsStruct(saltsField reflect.Value, saltsType reflect.Type, valueField reflect.Value) (err error) {
	if saltsType.Kind() != reflect.Struct {
		return fmt.Errorf("Invalid type (%s) for field", saltsType.String())
	}
	saltsField.Set(reflect.New(saltsType))
	err = FillSalts(valueField.Interface().(proto.Message), saltsField.Interface().(proto.Message))
	return
}

func handleFillSaltsValue(saltsField reflect.Value) (err error) {
	if reflect.TypeOf(saltsField.Interface()) != reflect.TypeOf([]uint8{}) {
		return fmt.Errorf("Invalid type (%s) for field", reflect.TypeOf(saltsField.Interface()).String())
	}
	newSalt := NewSalt()
	saltVal := reflect.ValueOf(newSalt)
	saltsField.Set(saltVal)
	return
}
