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


### Nested and Repeated Structures
Currently the library supports Nested Structs and Repeated/List Fields
See examples here: `examples/documents/example.proto`

## Proof format - Standard
This library defines a proof format that ensures both human readable, concise and secure Merkle proofs:

```js,
{  
    "property":"ValueA",
    "value":"Example",
    "salt":"1VWQFUGCXl1AYS0iAULHQow4XEjgJF/TpAuOO2Rnm+E=",
    "hashes":[  
        { "right":"kYXAGhDdPiFMq1ZQMOZiKmSf1S1eHNgJ6BIPSIExOj8=" },
        { "left":"GDgT7Km6NK6k4N/Id4CZXErL3p6clNX7sVnlNyegdG0=" },
        { "right":"qOZzS+YM8t1OfC87zEKgkKz6q0f3wwk5+ed+PR/2cDA=" }
    ]
}
```

## Proof format - hashed ordered
This implementation allows for more concise representation of proofs, saving some space that is valuable for on-chain verifications
```js,
{
    "property":"ValueA",
    "value":"Example",
    "salt":"1VWQFUGCXl1AYS0iAULHQow4XEjgJF/TpAuOO2Rnm+E=",
    "hashes":[  
        "kYXAGhDdPiFMq1ZQMOZiKmSf1S1eHNgJ6BIPSIExOj8=",
        "GDgT7Km6NK6k4N/Id4CZXErL3p6clNX7sVnlNyegdG0=",
        "qOZzS+YM8t1OfC87zEKgkKz6q0f3wwk5+ed+PR/2cDA="
    ]
}

```

There are a few things to note:
* Correspondent Salts Protobuf should have an additional field for each repeated field that exists in the original 
  protobuf document. See examples under `examples/documents/example.proto`
* When calculating the hash of the leaf, the dot notation of the property, the value and salt should
  be concatenated to produce the hash.
* The default proof expects values of documents to be salted to prevent rainbow table lookups.
* The value is included in the file as a string value not a native type. 


## Why protobuf?

Google's [protobuf](https://developers.google.com/protocol-buffers/docs/gotutorial) is a space efficient and fast format
to serialize data in a portable way. It's easy to generate JSON out of

## Tree Options
### EnableHashSorting
As described above, this is the flag to pass to implement a merkle tree with sorted hashes

### SaltsLengthSuffix
As precise proofs support repeated fields, when generating the merkle tree we need to add a leave that represents the length of the slice. 

The default suffix is `Length`, although it is customizable so it does not collide with potential field names of your own proto structs.

When creating the tree instance:
```
doctree := proofs.NewDocumentTree(proofs.TreeOptions{SaltsLengthSuffix: "CustomSuffixLength"})
```

## Usage:

See below code sample (`examples/simple.go`) for a usage example.

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
  
  //doctree := proofs.NewDocumentTree(merkle.TreeOptions{EnableHashSorting:true})
  //doctree := proofs.NewDocumentTree(proofs.TreeOptions{SaltsLengthSuffix: "CustomSuffixLength"})
  doctree := proofs.NewDocumentTree(proofs.TreeOptions{})
	doctree.FillTree(&document, &salts)
	fmt.Printf("Generated tree: %s\n", doctree.String())
	// Output:
	// Generated tree: DocumentTree with Hash [k4E4F9xgvzDPtCGE0yM1QRguleSxQX6sZ14VTYAYVTk=] and [5] leaves
	
	proof, _ := doctree.CreateProof("ValueA")
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))
        // Output:
        // {"property":"ValueA","value":"Foo","salt":"YSJ0pFJ4fk0gYsCOU2zLC1xAcqSDcw7tdV4M5ydlCNw=","hashes":[{"right":"anfIr8Oa4PjWQsf2qFLIGgFBeBphTI+RGBaKp8F6Fw0="},{"left":"B+/DkYDB2vvYAuw9GTbVk7jpxM2vPddxsbhldM1wOus="},{"right":"hCkGp+gqakfRE1aLg4j4mA9eAvKn0LbulLOAKUVLSCg="}]}


	valid, _ := doctree.ValidateProof(&proof)
        // Output:
        // Proof validated: true
```

### Missing features
The following features are being worked on:
* Add support for more types, currently only timestamp.Timestamp, []byte, int64 and string types are supported
