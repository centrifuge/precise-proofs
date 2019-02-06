package converter

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stefanhans/precise-proofs/examples/documents"
)

func equalLiteralPaths(lp1 []string, lp2 []string) bool {
	return strings.Join(lp1, "") == strings.Join(lp2, "")
}

func equalBinaryPaths(bp1 [][]uint64, bp2 [][]uint64) bool {
	if len(bp1) != len(bp2) {
		return false
	}
	for i := 0; i < len(bp1); i++ {
		if !equalBinaryPath(bp1[i], bp2[i]) {
			return false
		}
	}
	return true
}

// Just for coverage's sake
func TestString(t *testing.T) {
	t.Run("", func(t *testing.T) {

		protoType := ProtoType{
			MessageType: reflect.TypeOf(""),
		}

		_ = fmt.Sprint(protoType)
	})
}

func TestHandleType(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
		literalPath []string
	}

	testCases = map[string]struct {
		messageType interface{}
		literalPath []string
	}{
		"SimpleLeaves": {
			messageType: documentspb.SimpleLeaves{},
			literalPath: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o"},
		},
	}
	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			if !equalLiteralPaths(protoType.LiteralPath, tc.literalPath) {
				t.Errorf("unexpected literal path: expected %v received %v\n", tc.literalPath, protoType.LiteralPath)
				return
			}
		})
	}

	t.Run("Default", func(t *testing.T) {

		protoType := ProtoType{
			MessageType: reflect.TypeOf(documentspb.SimpleLeaves{}),
		}

		err := protoType.init()
		if err != nil {
			t.Errorf("protoType.init(): unexpected error: %v\n", err)
			return
		}

		err = protoType.handleType(reflect.TypeOf(complex(0.0, 0.0)))
		if err == nil {
			t.Errorf("protoType.handleType(): expected error not raised\n")
			return
		}
	})
}

func TestHandleStruct(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}

	testCases = map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}{
		"message type is nil":       {},
		"message type is no struct": {messageType: ""},
		"ExampleOfRecursiveStruct":  {messageType: documentspb.ExampleOfRecursiveStruct{}},
		"ExampleOfRecursiveSlice":   {messageType: documentspb.ExampleOfRecursiveSlice{}},
	}
	t.Run("errors", func(t *testing.T) {

		t.Run("typ is nil", func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(documentspb.ExampleOfVerySimpleStruct{}),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			err = protoType.handleStruct(reflect.TypeOf(nil))
			if err != nil {
				t.Errorf("protoType.handleStruct(): unexpected error: %v\n", err)
				return
			}
			if protoType.MessageType != reflect.TypeOf(documentspb.ExampleOfVerySimpleStruct{}) {
				t.Errorf("unexpected typ: expected %v received %v\n", reflect.TypeOf(documentspb.ExampleOfVerySimpleStruct{}), protoType.MessageType)
				return
			}
		})
		t.Run("typ is no struct", func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(documentspb.ExampleOfVerySimpleStruct{}),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			err = protoType.handleStruct(reflect.TypeOf(""))
			if err == nil {
				t.Errorf("protoType.handleStruct(): expected error not raised\n")
				return
			}
		})

		for n, tc := range testCases {
			t.Run(n, func(t *testing.T) {

				protoType := ProtoType{
					MessageType: reflect.TypeOf(tc.messageType),
				}

				err := protoType.init()
				if err == nil {
					t.Errorf("protoType.init(): expected error not raised\n")
					return
				}
			})
		}
	})

	testCases = map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}{
		"ExampleOfVerySimpleStruct": {
			messageType: documentspb.ExampleOfVerySimpleStruct{},
			literalPath: []string{"VSstring", "VSint32"},
			binaryPath:  [][]uint64{{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 1}},
		},
		"ExampleOfSimpleStruct": {
			messageType: documentspb.ExampleOfSimpleStruct{},
			literalPath: []string{"Sstring", "Sint32", "Sbytes", "Sstruct", "Sstruct.VSstring", "Sstruct.VSint32"},
			binaryPath: [][]uint64{
				{0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 2},
				{0, 0, 0, 0, 0, 0, 0, 3},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
		"ExampleOfCascadingStruct": {
			messageType: documentspb.ExampleOfCascadingStruct{},
			literalPath: []string{"CSstring", "CSstructA",
				"CSstructA.CSstring",
				"CSstructA.CSstructB",
				"CSstructA.CSstructB.CSstring",
				"CSstructA.CSstructB.CSint32",
				"CSstructA.CSstructB.CSbytes",
			},
			binaryPath: [][]uint64{
				{0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2},
			},
		},
	}
	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			if !equalLiteralPaths(protoType.LiteralPath, tc.literalPath) {
				t.Errorf("unexpected literal path: expected %v received %v\n", tc.literalPath, protoType.LiteralPath)
				return
			}

			if !equalBinaryPaths(protoType.BinaryPath, tc.binaryPath) {
				t.Errorf("unexpected binary path: expected %v received %v\n", tc.binaryPath, protoType.BinaryPath)
				return
			}
		})
	}
}

func TestHandleSlice(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}

	testCases = map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}{
		"message type is nil":       {messageType: reflect.TypeOf(nil)},
		"message type is no struct": {messageType: reflect.TypeOf("")},
		"type is no slice":          {messageType: documentspb.ExampleOfVerySimpleStruct{}},
		"ExampleOfRecursiveSlice":   {messageType: documentspb.ExampleOfRecursiveSlice{}},
	}
	t.Run("errors", func(t *testing.T) {

		for n, tc := range testCases {
			t.Run(n, func(t *testing.T) {

				protoType := ProtoType{
					MessageType: reflect.TypeOf(tc.messageType),
				}

				err := protoType.handleSlice(reflect.TypeOf(""))
				if err == nil {
					t.Errorf("protoType.handleSlice(): expected error not raised\n")
					return
				}

			})
		}
	})

	testCases = map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}{
		"ExamplesOfRepeated": {
			messageType: documentspb.ExamplesOfRepeated{},
			literalPath: []string{
				"Rstring[0]", "Rint32[0]", "Rbytes[0]", "Rstruct[0]",
				"Rstruct[0].VSstring", "Rstruct[0].VSint32"},
			binaryPath: [][]uint64{
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			if !equalLiteralPaths(protoType.LiteralPath, tc.literalPath) {
				t.Errorf("unexpected literal path: expected %v received %v\n", tc.literalPath, protoType.LiteralPath)
				return
			}

			if !equalBinaryPaths(protoType.BinaryPath, tc.binaryPath) {
				t.Errorf("unexpected binary path: expected %v received %v\n", tc.binaryPath, protoType.BinaryPath)
				return
			}
		})
	}
}

func TestHandleMap(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}

	testCases = map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}{
		"message type is nil":       {messageType: reflect.TypeOf(nil)},
		"message type is no struct": {messageType: reflect.TypeOf("")},
		"type is no map":            {messageType: documentspb.ExampleOfVerySimpleStruct{}},
	}
	t.Run("errors", func(t *testing.T) {

		for n, tc := range testCases {
			t.Run(n, func(t *testing.T) {

				protoType := ProtoType{
					MessageType: reflect.TypeOf(tc.messageType),
				}

				err := protoType.handleMap(reflect.TypeOf(""))
				if err == nil {
					t.Errorf("protoType.handleMap(): expected error not raised\n")
					return
				}
			})
		}
	})

	testCases = map[string]struct {
		messageType interface{}
		literalPath []string
		binaryPath  [][]uint64
	}{
		"ExamplesOfSimpleMaps": {messageType: documentspb.ExamplesOfSimpleMaps{},
			literalPath: []string{
				"KstringVstring['']", "KstringVint32['']", "KstringVbytes['']",
				"KstringVexampleOfVerySimpleStruct['']",
				"KstringVexampleOfVerySimpleStruct[''].VSstring",
				"KstringVexampleOfVerySimpleStruct[''].VSint32",
				"Kint32Vstring[0]", "Kint32Vint32[0]", "Kint32Vbytes[0]",
				"Kint32VexampleOfVerySimpleStruct[0]",
				"Kint32VexampleOfVerySimpleStruct[0].VSstring",
				"Kint32VexampleOfVerySimpleStruct[0].VSint32",
			},
			binaryPath: [][]uint64{
				{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			if !equalLiteralPaths(protoType.LiteralPath, tc.literalPath) {
				t.Errorf("unexpected literal path: expected %v received %v\n", tc.literalPath, protoType.LiteralPath)
				return
			}

			if !equalBinaryPaths(protoType.BinaryPath, tc.binaryPath) {
				t.Errorf("unexpected binary path: expected %v received %v\n", tc.binaryPath, protoType.BinaryPath)
				return
			}
		})
	}
}

func TestGetBinaryPath(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
		literal     string
	}

	testCases = map[string]struct {
		messageType interface{}
		literal     string
	}{
		"empty literal": {
			messageType: ""},
		"not found": {
			messageType: "",
			literal:     "unknown"},
	}
	t.Run("errors", func(t *testing.T) {

		for n, tc := range testCases {
			t.Run(n, func(t *testing.T) {

				protoType := ProtoType{
					MessageType: reflect.TypeOf(tc.messageType),
				}

				_, err := protoType.getBinaryPath(tc.literal)
				if err == nil {
					t.Errorf("protoType.getBinaryPath(%q): expected error not raised\n", tc.literal)
					return
				}
			})
		}
	})

	testCases = map[string]struct {
		messageType interface{}
		literal     string
	}{
		"ExampleOfVerySimpleStruct": {
			messageType: documentspb.ExampleOfVerySimpleStruct{},
		},
		"ExampleOfSimpleStruct": {
			messageType: documentspb.ExampleOfSimpleStruct{},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			for i, path := range protoType.LiteralPath {
				binaryPath, err := protoType.getBinaryPath(path)
				if err != nil {
					t.Errorf("getBinaryPath: unexpected error: %v\n", err)
				}
				if !equalBinaryPath(protoType.BinaryPath[i], binaryPath) {
					t.Errorf("unexpected binary path: expected %v received %v\n", protoType.BinaryPath[i], binaryPath)
					return
				}
			}
		})
	}
}

func TestGetLiteralPath(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
		binary      []uint64
	}

	testCases = map[string]struct {
		messageType interface{}
		binary      []uint64
	}{
		"empty literal": {
			messageType: ""},
		"not found": {
			messageType: "",
			binary:      []uint64{1, 2, 3, 4, 5, 6, 7, 8}},
	}
	t.Run("errors", func(t *testing.T) {

		for n, tc := range testCases {
			t.Run(n, func(t *testing.T) {

				protoType := ProtoType{
					MessageType: reflect.TypeOf(tc.messageType),
				}

				_, err := protoType.getLiteralPath(tc.binary)
				if err == nil {
					t.Errorf("protoType.getLiteralPath(%v): expected error not raised\n", tc.binary)
					return
				}
			})
		}
	})

	testCases = map[string]struct {
		messageType interface{}
		binary      []uint64
	}{
		"ExampleOfVerySimpleStruct": {
			messageType: documentspb.ExampleOfVerySimpleStruct{},
		},
		"ExampleOfSimpleStruct": {
			messageType: documentspb.ExampleOfSimpleStruct{},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			for i, path := range protoType.BinaryPath {
				literalPath, err := protoType.getLiteralPath(path)
				if err != nil {
					t.Errorf("getLiteralPath: unexpected error: %v\n", err)
				}
				if protoType.LiteralPath[i] != literalPath {
					t.Errorf("unexpected literal path: expected %v received %v\n", protoType.LiteralPath[i], literalPath)
					return
				}
			}
		})
	}
}

func TestMessageTypeConversion(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
	}

	testCases = map[string]struct {
		messageType interface{}
	}{
		"SimpleLeaves": {
			messageType: documentspb.SimpleLeaves{},
		},
		"ExampleOfVerySimpleStruct": {
			messageType: documentspb.ExampleOfVerySimpleStruct{},
		},
		"ExampleOfSimpleStruct": {
			messageType: documentspb.ExampleOfSimpleStruct{},
		},
		"ExampleOfCascadingStruct": {
			messageType: documentspb.ExampleOfCascadingStruct{},
		},
		"ExamplesOfSimpleMaps": {
			messageType: documentspb.ExamplesOfSimpleMaps{},
		},
		"ExamplesOfRepeated": {
			messageType: documentspb.ExamplesOfRepeated{},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			for _, lPath := range protoType.LiteralPath {
				binaryPath, err := protoType.getBinaryPath(lPath)
				if err != nil {
					t.Errorf("getBinaryPath: unexpected error: %v\n", err)
				}
				literalPath, err := protoType.getLiteralPath(binaryPath)
				if err != nil {
					t.Errorf("getLiteralPath: unexpected error: %v\n", err)
				}

				if lPath != literalPath {
					t.Errorf("unexpected literal path: expected %v received %v\n", lPath, literalPath)
					return
				}
			}

			for _, bPath := range protoType.BinaryPath {
				literalPath, err := protoType.getLiteralPath(bPath)
				if err != nil {
					t.Errorf("getLiteralPath: unexpected error: %v\n", err)
				}
				binaryPath, err := protoType.getBinaryPath(literalPath)
				if err != nil {
					t.Errorf("getBinaryPath: unexpected error: %v\n", err)
				}

				if !equalBinaryPath(bPath, binaryPath) {
					t.Errorf("unexpected binary path: expected %v received %v\n", bPath, binaryPath)
					return
				}
			}
		})
	}
}

func TestGetBinaryProperty(t *testing.T) {

	var testCases map[string]struct {
		messageType       interface{}
		literalProperties []string
		binaryProperties  [][]uint64
	}

	testCases = map[string]struct {
		messageType       interface{}
		literalProperties []string
		binaryProperties  [][]uint64
	}{
		"ExampleOfVerySimpleStruct": {
			messageType:       documentspb.ExampleOfVerySimpleStruct{},
			literalProperties: []string{"VSstring", "VSint32"},
			binaryProperties:  [][]uint64{{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 1}},
		},
	}

	t.Run("errors", func(t *testing.T) {

		t.Run("literal not found", func(t *testing.T) {
			protoType := ProtoType{
				MessageType: reflect.TypeOf(documentspb.ExampleOfVerySimpleStruct{}),
			}

			_, err := protoType.getBinaryPath("unknown")
			if err == nil {
				t.Errorf("protoType.handleMap(): expected error not raised\n")
				return
			}
		})
		t.Run("binary not found", func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(documentspb.ExampleOfVerySimpleStruct{}),
			}

			_, err := protoType.getLiteralPath([]uint64{1, 2, 3, 4, 5, 6, 7})
			if err == nil {
				t.Errorf("protoType.handleMap(): expected error not raised\n")
				return
			}

		})
	})

	t.Run("Uninitialized", func(t *testing.T) {

		for _, tc := range testCases {
			prototypes[reflect.TypeOf(tc.messageType)] = nil
			t.Run("nil", func(t *testing.T) {

				for i, literal := range tc.literalProperties {
					binaryProperty, err := GetBinaryProperty(reflect.TypeOf(tc.messageType), literal)
					if err != nil {
						t.Errorf("unexpected error: %v\n", err)
						return
					}
					if !equalBinaryPath(binaryProperty, tc.binaryProperties[i]) {
						t.Errorf("unexpected binary property: expected %v received %v\n", tc.binaryProperties[i], binaryProperty)
						return
					}
				}
			})

			prototypes[reflect.TypeOf("")] = nil
			t.Run("empty string", func(t *testing.T) {

				for i, literal := range tc.literalProperties {
					_, err := GetBinaryProperty(reflect.TypeOf(""), literal)
					if err == nil {
						t.Errorf("unexpected error: %v\n", err)
						return
					}
					_, err = GetLiteralProperty(reflect.TypeOf(""), tc.binaryProperties[i])
					if err == nil {
						t.Errorf("unexpected error: %v\n", err)
						return
					}
				}
			})
		}
	})

	testCases = map[string]struct {
		messageType       interface{}
		literalProperties []string
		binaryProperties  [][]uint64
	}{
		"ExampleOfVerySimpleStruct": {
			messageType:       documentspb.ExampleOfVerySimpleStruct{},
			literalProperties: []string{"VSstring", "VSint32"},
			binaryProperties:  [][]uint64{{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 1}},
		},
		"ExampleOfSimpleStruct": {
			messageType:       documentspb.ExampleOfSimpleStruct{},
			literalProperties: []string{"Sstring", "Sint32", "Sbytes", "Sstruct", "Sstruct.VSstring", "Sstruct.VSint32"},
			binaryProperties: [][]uint64{
				{0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 2},
				{0, 0, 0, 0, 0, 0, 0, 3},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			for i, literal := range tc.literalProperties {
				binaryProperty, err := GetBinaryProperty(reflect.TypeOf(tc.messageType), literal)
				if err != nil {
					t.Errorf("unexpected error: %v\n", err)
					return
				}
				if !equalBinaryPath(binaryProperty, tc.binaryProperties[i]) {
					t.Errorf("unexpected binary property: expected %v received %v\n", tc.binaryProperties[i], binaryProperty)
					return
				}
			}
		})
	}
}

func TestGetLiteralProperty(t *testing.T) {

	var testCases map[string]struct {
		messageType       interface{}
		literalProperties []string
		binaryProperties  [][]uint64
	}

	testCases = map[string]struct {
		messageType       interface{}
		literalProperties []string
		binaryProperties  [][]uint64
	}{
		"ExampleOfVerySimpleStruct": {
			messageType:       documentspb.ExampleOfVerySimpleStruct{},
			literalProperties: []string{"VSstring", "VSint32"},
			binaryProperties:  [][]uint64{{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 1}},
		},
		"ExampleOfSimpleStruct": {
			messageType:       documentspb.ExampleOfSimpleStruct{},
			literalProperties: []string{"Sstring", "Sint32", "Sbytes", "Sstruct", "Sstruct.VSstring", "Sstruct.VSint32"},
			binaryProperties: [][]uint64{
				{0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 1},
				{0, 0, 0, 0, 0, 0, 0, 2},
				{0, 0, 0, 0, 0, 0, 0, 3},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1},
			},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			for i, binary := range tc.binaryProperties {
				literalProperty, err := GetLiteralProperty(reflect.TypeOf(tc.messageType), binary)
				if err != nil {
					t.Errorf("unexpected error: %v\n", err)
					return
				}
				if literalProperty != tc.literalProperties[i] {
					t.Errorf("unexpected literal property: expected %v received %v\n", tc.literalProperties[i], literalProperty)
					return
				}
			}
		})
	}
}

func TestMessagePropertyConversion(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
	}

	testCases = map[string]struct {
		messageType interface{}
	}{
		"SimpleLeaves": {
			messageType: documentspb.SimpleLeaves{},
		},
		"ExampleOfVerySimpleStruct": {
			messageType: documentspb.ExampleOfVerySimpleStruct{},
		},
		"ExampleOfSimpleStruct": {
			messageType: documentspb.ExampleOfSimpleStruct{},
		},
		"ExampleOfCascadingStruct": {
			messageType: documentspb.ExampleOfCascadingStruct{},
		},
		"ExamplesOfSimpleMaps": {
			messageType: documentspb.ExamplesOfSimpleMaps{},
		},
		"ExamplesOfRepeated": {
			messageType: documentspb.ExamplesOfRepeated{},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			for _, lPath := range protoType.LiteralPath {
				binaryPath, err := GetBinaryProperty(protoType.MessageType, lPath)
				if err != nil {
					t.Errorf("GetBinaryProperty: unexpected error: %v\n", err)
				}
				literalPath, err := GetLiteralProperty(protoType.MessageType, binaryPath)
				if err != nil {
					t.Errorf("getLiteralPath: unexpected error: %v\n", err)
				}

				if lPath != literalPath {
					t.Errorf("unexpected literal path: expected %v received %v\n", lPath, literalPath)
					return
				}
			}

			for _, bPath := range protoType.BinaryPath {
				literalPath, err := protoType.getLiteralPath(bPath)
				if err != nil {
					t.Errorf("getLiteralPath: unexpected error: %v\n", err)
				}
				binaryPath, err := protoType.getBinaryPath(literalPath)
				if err != nil {
					t.Errorf("getBinaryPath: unexpected error: %v\n", err)
				}

				if !equalBinaryPath(bPath, binaryPath) {
					t.Errorf("unexpected binary path: expected %v received %v\n", bPath, binaryPath)
					return
				}
			}
		})
	}
}

func TestDocumentPropertyConversion(t *testing.T) {

	var testCases map[string]struct {
		messageType interface{}
	}

	testCases = map[string]struct {
		messageType interface{}
	}{
		"ExampleDocument": {
			messageType: documentspb.ExampleDocument{},
		},
		"AllFieldTypes": {
			messageType: documentspb.AllFieldTypes{},
		},
		"AllFieldTypesSalts": {
			messageType: documentspb.AllFieldTypesSalts{},
		},
		"SimpleItem": {
			messageType: documentspb.SimpleItem{},
		},
		"RepeatedItem": {
			messageType: documentspb.RepeatedItem{},
		},
		"SimpleMap": {
			messageType: documentspb.SimpleMap{},
		},
		"SimpleStringMap": {
			messageType: documentspb.SimpleStringMap{},
		},
		"NestedMap": {
			messageType: documentspb.NestedMap{},
		},
		"SimpleEntry": {
			messageType: documentspb.SimpleEntry{},
		},
		"SimpleEntries": {
			messageType: documentspb.SimpleEntries{},
		},
		"Entry": {
			messageType: documentspb.Entry{},
		},
		"Entries": {
			messageType: documentspb.Entries{},
		},
		"BytesKeyEntry": {
			messageType: documentspb.BytesKeyEntry{},
		},
		"BytesKeyEntries": {
			messageType: documentspb.BytesKeyEntries{},
		},
		"TwoLevelRepeatedDocument": {
			messageType: documentspb.TwoLevelRepeatedDocument{},
		},
		"SimpleRepeatedDocument": {
			messageType: documentspb.SimpleRepeatedDocument{},
		},
		"SimpleMapDocument": {
			messageType: documentspb.SimpleMapDocument{},
		},
		"TwoLevelItem": {
			messageType: documentspb.TwoLevelItem{},
		},
		"NestedRepeatedDocument": {
			messageType: documentspb.NestedRepeatedDocument{},
		},
		"InvalidHashedFieldDocument": {
			messageType: documentspb.InvalidHashedFieldDocument{},
		},
		"LongDocument": {
			messageType: documentspb.LongDocument{},
		},
		"Integers": {
			messageType: documentspb.Integers{},
		},
	}

	for n, tc := range testCases {
		t.Run(n, func(t *testing.T) {

			protoType := ProtoType{
				MessageType: reflect.TypeOf(tc.messageType),
			}

			err := protoType.init()
			if err != nil {
				t.Errorf("protoType.init(): unexpected error: %v\n", err)
				return
			}

			for _, lPath := range protoType.LiteralPath {
				binaryPath, err := GetBinaryProperty(protoType.MessageType, lPath)
				if err != nil {
					t.Errorf("GetBinaryProperty: unexpected error: %v\n", err)
				}
				literalPath, err := GetLiteralProperty(protoType.MessageType, binaryPath)
				if err != nil {
					t.Errorf("getLiteralPath: unexpected error: %v\n", err)
				}

				if lPath != literalPath {
					t.Errorf("unexpected literal path: expected %v received %v\n", lPath, literalPath)
					return
				}
			}

			for _, bPath := range protoType.BinaryPath {
				literalPath, err := protoType.getLiteralPath(bPath)
				if err != nil {
					t.Errorf("getLiteralPath: unexpected error: %v\n", err)
				}
				binaryPath, err := protoType.getBinaryPath(literalPath)
				if err != nil {
					t.Errorf("getBinaryPath: unexpected error: %v\n", err)
				}

				if !equalBinaryPath(bPath, binaryPath) {
					t.Errorf("unexpected binary path: expected %v received %v\n", bPath, binaryPath)
					return
				}
			}

			// For manual checking: go test -v -run TestDocumentPropertyConversion | grep CHECK | awk -F"CHECK: " '{ print $2 }'
			// fmt.Printf("CHECK: %v\nCHECK: %v\nCHECK: %v\nCHECK: \n", protoType.MessageType, protoType.LiteralPath, protoType.BinaryPath)
		})
	}
}
