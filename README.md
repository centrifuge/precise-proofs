Precise Proofs
==============
[![GoDoc](https://godoc.org/github.com/centrifuge/precise-proofs/proofs?status.svg)](https://godoc.org/github.com/centrifuge/precise-proofs/proofs)
[![Travis CI](https://api.travis-ci.org/centrifuge/precise-proofs.svg?branch=master)](https://travis-ci.org/centrifuge/precise-proofs)
[![codecov](https://codecov.io/gh/centrifuge/precise-proofs/branch/master/graph/badge.svg)](https://codecov.io/gh/centrifuge/precise-proofs)

Read the [introduction on Precise-Proofs](https://medium.com/centrifuge/introducing-precise-proofs-create-validate-field-level-merkle-proofs-a31af9220df0)

Precise-Proofs is a library for creating Merkle proofs out of protobuf messages. It
handles flattening of objects, ordering the fields by label and creating shareable and
independently verifiable proofs.

This library takes arbitrary protobuf messages and makes sure a Merkle tree can be reliably calculated
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
to serialize data in a portable way. It's easy to generate JSON out of.

## Binary fields encoding
For `[]byte` fields the default encoding used for tree and proof generation is Hexadecimal using <https://godoc.org/github.com/ethereum/go-ethereum/common/hexutil>

## Usage:

See below code sample (`examples/simple.go`) for a usage example. For detailed usage, check godocs.

```go,

    // ExampleDocument is a protobuf message
    document := documentspb.ExampleDocument{
        Value1:      1,
        ValueA:      "Foo",
        ValueB:      "Bar",
        ValueBytes1: []byte("foobar"),
        Name: &documentspb.Name{
            First: "Hello, ",
            Last:  "World",
        },
        PaddingA:    "WillBePadded",
    }

    blake2b256, _ := blake2b.New256([]byte{1, 2, 3, 4})
    doctree, _ := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New(), LeafHash: blake2b256})
    doctree.AddLeavesFromDocument(&document)
    doctree.Generate()
    fmt.Printf("Generated tree: %s\n", doctree.String())

    // Generate the proof for a field. In this case the field called "ValueA".
    proof, _ := doctree.CreateProof("valueA")
    proofJson, _ := json.Marshal(proof)
    fmt.Println("Proof:\n", string(proofJson))

    // Validate the proof that was just generated
    valid, _ := doctree.ValidateProof(&proof)
    fmt.Printf("Proof validated: %v\n", valid)

    // Fixed Length Tree
    doctree2 := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New(), LeafHash: blake2b256, TreeDepth: 5})
    fmt.Printf("\n\nNon empty leaves number of generated tree should be %d\n", 1<<5)
    doctree2.AddLeavesFromDocument(&document)
    doctree2.Generate()
    fmt.Printf("Non empty leaves number of the tree is %d\n", len(doctree2.GetLeaves()))

    // Generate the actual proof for a field. In this case the field called "ValueA".
    proof, _ = doctree2.CreateProof("valueA")
    proofJson, _ = json.Marshal(proof)
    fmt.Println("Proof:\n", string(proofJson))

    // Validate the proof that was just generated
    valid, _ = doctree2.ValidateProof(&proof)

```

## Development
### Building protobuf messages
If the protobuf messages are ever changed, the recommended procedure is to build them using prototools. Use
prototools version 1.3.0 and execute the command `prototol generate` to udpate both the example and the proofs
messages.


