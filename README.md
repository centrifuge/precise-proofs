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

## Usage:

See below code sample (`examples/simple.go`) for a usage example. For detailed usage, check godocs.

```go,
        // ExampleDocument is a protobuf message
	document := documentspb.ExampleDocument{
		Value1:      1,
		ValueA:      "Foo",
		ValueB:      "Bar",
		ValueBytes1: []byte("foobar"),
	}

	// The FillSalts method is a helper function that fills all fields with 32
	// random bytes. SaltedExampleDocument is a protobuf message that has the
	// same structure as ExampleDocument but has all `bytes` field types.
	salts := documentspb.SaltedExampleDocument{}
	FillSalts(&document, &salts)

	doctree := NewDocumentTree(TreeOptions{Hash: sha256.New()})
	doctree.AddLeavesFromDocument(&document, &salts)
	doctree.Generate()
	fmt.Printf("Generated tree: %s\n", doctree.String())

	proof, _ := doctree.CreateProof("ValueA")
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	valid, _ := doctree.ValidateProof(&proof)

	fmt.Printf("Proof validated: %v\n", valid)
```

