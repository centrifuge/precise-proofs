package documentspb

//go:generate protoc -I $PROTOBUF/src/ -I. -I $GOPATH/src --go_out=$GOPATH/src/ example.proto

import (
	"time"

	"github.com/golang/protobuf/ptypes"
)

var salt []byte = []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225}

var LongDocumentExample LongDocument = LongDocument{Value0: 1, Value1: 2, Value2: 3, Value3: 4, Value4: 5, Value5: 6, Value6: 7, Value7: 8, Value8: 9, Value9: 10, ValueA: 11, ValueB: 12, ValueC: 13, ValueD: 14, ValueE: 15}

var FilledExampleDocument ExampleDocument = ExampleDocument{
	ValueA: "Example",
}


var ExampleTimeString string = "2018-04-10T01:23:12.697116Z"

func NewAllFieldTypes() *AllFieldTypes {
	m := AllFieldTypes{}
	t := time.Now()
	t.UnmarshalJSON([]byte(ExampleTimeString))
	now, _ := ptypes.TimestampProto(t)
	m.StringValue = "foobar"
	m.TimeStampValue = now
	return &m
}

var ExampleFilledRepeatedDocument = SimpleRepeatedDocument{
	ValueA: "ValueAA",
	ValueB: "ValueBB",
	ValueC: []string{"ValueCA", "ValueCB"},
}

var ExampleFilledTwoLevelRepeatedDocument = TwoLevelRepeatedDocument{
	ValueA: "ValueAA",
	ValueB: []*RepeatedItem{{ValueA: []*SimpleItem{{ValueA: "ValueBAAA"}, {ValueA: "ValueBAAB"}}, ValueB: "ValueBBA"}},
}

var ExampleFilledNestedRepeatedDocument = NestedRepeatedDocument{
	ValueA: "ValueAA",
	ValueB: "ValueBB",
	ValueC: []*SimpleItem{{ValueA: "ValueCA"}, {ValueA: "ValueCB"}},
	ValueD: &TwoLevelItem{ValueA: &SimpleItem{ValueA: "ValueDAA"}, ValueB: "ValueDB"},
}

var ExampleSimpleMapDocument = SimpleMapDocument{
	ValueA: "ValueAA",
	ValueB: "ValueBB",
	ValueC: map[string]string{
		"ValueCAKey": "ValueCAValue",
		"ValueCBKey": "ValueCBValue",
	},
	ValueD: map[int32]string{
		-1: "negative one",
		0:  "zero",
		1:  "one",
	},
}

