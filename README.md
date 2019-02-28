Precise Proofs
==============
[![GoDoc](https://godoc.org/github.com/centrifuge/precise-proofs/proofs?status.svg)](https://godoc.org/github.com/centrifuge/precise-proofs/proofs)
[![Travis CI](https://api.travis-ci.org/centrifuge/precise-proofs.svg?branch=master)](https://travis-ci.org/centrifuge/precise-proofs)
[![codecov](https://codecov.io/gh/centrifuge/precise-proofs/branch/master/graph/badge.svg)](https://codecov.io/gh/centrifuge/precise-proofs)

Read the [introduction on Precise-Proofs](https://medium.com/centrifuge/introducing-precise-proofs-create-validate-field-level-merkle-proofs-a31af9220df0)

Precise-Proofs is a library for creating Merkle proofs out of protobuf messages. It
handles flattening of objects, ordering the fields by label and creating shareable and
independently verifiable proofs.

This library takes arbitrary protobuf messages and makes sure a Merkle tree can be reliable calculated
from the values with each value representing a leaf in the tree.
```js,
{
    "Amount": "$1500",
    "InvoiceDate": "2018-03-01",
    "DueDate": "2018-08-01",
    "Country": "USA",
    "Supplier": "Arbor Tree Inc",
    "Buyer": "ACME Paper Inc",
    "Status": "APPROVED"
}
```

Above example would result in the following tree:

![Merkle tree example](https://raw.githubusercontent.com/centrifuge/precise-proofs/master/docs/tree.png)

## Why protobuf?

Google's [protobuf](https://developers.google.com/protocol-buffers/docs/gotutorial) is a space efficient and fast format
to serialize data in a portable way. It's easy to generate JSON out of

## Binary fields encoding
For `[]byte` fields the default encoding used for tree and proof generation is Hexadecimal using https://godoc.org/github.com/ethereum/go-ethereum/common/hexutil

## Usage:

See below code sample (`examples/simple.go`) for a usage example. For detailed usage, check godocs.

```go,
  // ContainSalts is a protobuf message which contain salts message
	document := documentspb.ContainSalts{
		ValueA:     "valueAValue",
		ValueB:     10,
		Salts:      []*proofspb.Salt{{Compact: []byte{0,0,0,1}, Value: []byte{0x1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x2}},{Compact: []byte{0,0,0,2}, Value: []byte{0x3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x4}}},
	}

	doctree := NewDocumentTree(TreeOptions{Hash: sha256.New()})
	doctree.AddLeavesFromDocument(&document)

	doctree.Generate()
	fmt.Printf("Generated tree: %s\n", doctree.String())

	proof, _ := doctree.CreateProof("valueA")
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	valid, _ := doctree.ValidateProof(&proof)

	fmt.Printf("Proof validated: %v\n", valid)
```

## Development
### Building protobuf messages
If the protobuf messages are ever changed, the recommended procedure is to build them using prototools. Use
prototools version 1.3.0 and execute the command `prototol generate` to udpate both the example and the proofs
messages.


