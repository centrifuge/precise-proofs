// Package converter provides conversions between literal and binary properties of protocolbuffers' message types.
package converter

import (
	"fmt"
	"reflect"
	"strings"
)

var BinaryPrefix = []uint64{0, 0, 0, 0, 0, 0, 0}

func equalBinaryPath(bp1 []uint64, bp2 []uint64) bool {
	if len(bp1) != len(bp2) {
		return false
	}
	for i := 0; i < len(bp1); i++ {
		if bp1[i] != bp2[i] {
			return false
		}
	}
	return true
}

var prototypes = make(map[reflect.Type]*ProtoType)

// GetBinaryProperty converts a literal property of a message type into the corresponding binary property.
func GetBinaryProperty(messageTyp reflect.Type, literal string) ([]uint64, error) {
	protoType := prototypes[messageTyp]

	if protoType == nil {
		protoType = &ProtoType{MessageType: messageTyp}
		err := protoType.handleStruct(protoType.MessageType)
		if err != nil {
			return nil, fmt.Errorf("protoType.handleStruct(): unexpected error: %v\n", err)
		}
	}

	return protoType.getBinaryPath(literal)
}

// GetLiteralProperty converts a binary property of a message type into the corresponding literal property.
func GetLiteralProperty(messageTyp reflect.Type, binary []uint64) (string, error) {
	protoType := prototypes[messageTyp]

	if protoType == nil {
		protoType = &ProtoType{MessageType: messageTyp}
		err := protoType.handleStruct(protoType.MessageType)
		if err != nil {
			return "", fmt.Errorf("protoType.handleStruct(): unexpected error: %v\n", err)
		}
	}

	return protoType.getLiteralPath(binary)
}

type ProtoType struct {
	MessageType   reflect.Type
	Literal       string
	LiteralPath   []string
	Binary        []uint64
	BinaryPath    [][]uint64
	IsInitialized bool
}

// String shows the fields of a ProtoType instance.
func (protoType ProtoType) String() string {
	out := ""
	out += fmt.Sprintf("MessageType: %v\n", protoType.MessageType)
	out += fmt.Sprintf("Literal: %v\n", protoType.Literal)
	out += fmt.Sprintf("LiteralPath: %v\n", protoType.LiteralPath)
	out += fmt.Sprintf("Binary: %v\n", protoType.Binary)
	out += fmt.Sprintf("BinaryPath: %v\n", protoType.BinaryPath)
	out += fmt.Sprintf("IsInitialized: %v\n", protoType.IsInitialized)

	return out
}

func (protoType *ProtoType) init() error {
	err := protoType.handleStruct(protoType.MessageType)
	if err != nil {
		return fmt.Errorf("unexpected error: %v\n", err)
	}
	prototypes[protoType.MessageType] = protoType

	return nil
}

func (protoType *ProtoType) handleType(typ reflect.Type) error {
	switch typ.Kind() {
	case reflect.Struct:
		return protoType.handleStruct(typ)
	case reflect.Map:
		return protoType.handleMap(typ)
	case reflect.Ptr:
		// Resolve the pointer
		return protoType.handleType(typ.Elem())
	case reflect.Slice:
		return protoType.handleSlice(typ)
	case reflect.Uint32:
		return nil
	case reflect.Uint64:
		return nil
	case reflect.String:
		return nil
	case reflect.Float32:
		return nil
	case reflect.Float64:
		return nil
	case reflect.Int32:
		return nil
	case reflect.Int64:
		return nil
	case reflect.Bool:
		return nil
	default:
		return fmt.Errorf("unexpexted kind of type %v\n", typ.Kind())
	}
}

func (protoType *ProtoType) handleStruct(typ reflect.Type) error {

	// Root message type is nil
	if protoType.MessageType == nil {
		return fmt.Errorf("root type is nil\n")
	}

	// Root message type is not a struct
	if protoType.MessageType.Kind() != reflect.Struct {
		return fmt.Errorf("root type %v is not a struct\n", protoType.MessageType)
	}

	// Set root message type as type if needed
	if typ == nil {
		typ = protoType.MessageType
	} else {
		if typ.Kind() != reflect.Struct {
			return fmt.Errorf("%v is not a struct\n", typ)
		}
	}

	// Set struct field literal prefix
	var lPrefix string
	if protoType.Literal != "" {
		lPrefix = protoType.Literal + "."
	}

	// Set struct filed binary prefix
	var bPrefix []uint64
	if len(protoType.Binary) != 0 {
		bPrefix = protoType.Binary
	}

	for i := 0; i < typ.NumField(); i++ {

		if s, ok := typ.Field(i).Tag.Lookup("protobuf"); ok {

			protoType.Literal = lPrefix + strings.Split(strings.Split(s, "name=")[1], ",")[0]
			protoType.LiteralPath = append(protoType.LiteralPath, protoType.Literal)

			protoType.Binary = append(bPrefix, append(BinaryPrefix, uint64(i))...)
			protoType.BinaryPath = append(protoType.BinaryPath, protoType.Binary)

			// Exclude recursive structs
			if typ.Field(i).Type.Kind() == reflect.Ptr &&
				typ == typ.Field(i).Type.Elem() {
				return fmt.Errorf("error: %v is a recursive struct\n", typ)
			}
			// Exclude repeated recursive structs
			if typ.Field(i).Type.Kind() == reflect.Slice &&
				typ.Field(i).Type.Elem().Kind() == reflect.Ptr &&
				typ == typ.Field(i).Type.Elem().Elem() {
				return fmt.Errorf("error: %v is a repeated recursive struct\n", typ)
			}

			err := protoType.handleType(typ.Field(i).Type)
			if err != nil {
				return err
			}
		}
	}

	protoType.IsInitialized = true

	return nil
}

func (protoType *ProtoType) handleSlice(typ reflect.Type) error {

	// Root message type is nil
	if protoType.MessageType == nil {
		return fmt.Errorf("root type is nil\n")
	}

	// Root message type is not a struct
	if protoType.MessageType.Kind() != reflect.Struct {
		return fmt.Errorf("root type %v is not a struct\n", protoType.MessageType)
	}

	// Set root message type as type if needed
	if typ.Kind() != reflect.Slice {
		return fmt.Errorf("%v is not a slice\n", typ)
	}

	if typ == reflect.SliceOf(reflect.TypeOf(uint8(0))) {
		return nil
	}

	indexString := "[0]"
	protoType.Literal = protoType.Literal + indexString
	protoType.LiteralPath[len(protoType.LiteralPath)-1] = protoType.Literal

	indexBinary := []uint64{0, 0, 0, 0, 0, 0, 0, 0}
	protoType.Binary = append(protoType.Binary, indexBinary...)
	protoType.BinaryPath[len(protoType.BinaryPath)-1] = protoType.Binary

	return protoType.handleType(typ.Elem())
}

func (protoType *ProtoType) handleMap(typ reflect.Type) error {

	// Root message type is nil
	if protoType.MessageType == nil {
		return fmt.Errorf("root type is nil\n")
	}

	// Root message type is not a struct
	if protoType.MessageType.Kind() != reflect.Struct {
		return fmt.Errorf("root type %v is not a struct\n", protoType.MessageType)
	}

	// Set root message type as type if needed
	if typ.Kind() != reflect.Map {
		return fmt.Errorf("%v is not a map\n", typ)
	}

	indexString := "[0]"
	if typ.Key().Kind() == reflect.String {
		indexString = "['']"
	}
	protoType.Literal = protoType.Literal + indexString
	protoType.LiteralPath[len(protoType.LiteralPath)-1] = protoType.Literal

	indexBinary := []uint64{0, 0, 0, 0, 0, 0, 0, 0}
	protoType.Binary = append(protoType.Binary, indexBinary...)
	protoType.BinaryPath[len(protoType.BinaryPath)-1] = protoType.Binary

	return protoType.handleType(typ.Elem())
}

func (protoType *ProtoType) getBinaryPath(literalPath string) ([]uint64, error) {

	if !protoType.IsInitialized {
		err := protoType.init()
		if err != nil {
			return nil, fmt.Errorf("could not initialize ProtoType %v\n", protoType.MessageType)
		}
	}

	for i, path := range protoType.LiteralPath {
		if path == literalPath {
			return protoType.BinaryPath[i], nil
		}
	}

	return nil, fmt.Errorf("could not find literal %q in %v\n", literalPath, protoType.MessageType)
}

func (protoType *ProtoType) getLiteralPath(binaryPath []uint64) (string, error) {

	if !protoType.IsInitialized {
		err := protoType.init()
		if err != nil {
			return "", fmt.Errorf("could not initialize ProtoType %v\n", protoType.MessageType)
		}
	}

	for i, path := range protoType.BinaryPath {
		if equalBinaryPath(path, binaryPath) {
			return protoType.LiteralPath[i], nil
		}
	}

	return "", fmt.Errorf("could not find binary %q in %v\n", binaryPath, protoType.MessageType)
}
