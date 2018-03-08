package example

//go:generate protoc -I $PROTOBUF/src/ -I. -I $GOPATH/src --go_out=$GOPATH/src/ example.proto

var salt []byte = []byte{213, 85, 144, 21, 65, 130, 94, 93, 64, 97, 45, 34, 1, 66, 199, 66, 140, 56, 92, 72, 224, 36, 95, 211, 164, 11, 142, 59, 100, 103, 155, 225}
var LongDocumentExample LongDocument = LongDocument{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
var SaltedLongDocumentExample SaltedLongDocument = SaltedLongDocument{salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
	salt,
}

var FilledExampleDocument ExampleDocument = ExampleDocument{
	ValueA: "Example",
}

var ExampleDocumentSalts SaltedExampleDocument = SaltedExampleDocument{
	salt,
	salt,
	salt,
	salt,
	salt,
}
