Precise Proofs
==============
[![GoDoc](https://godoc.org/github.com/centrifuge/precise-proofs/preciseproofs?status.svg)](https://godoc.org/github.com/centrifuge/precise-proofs/preciseproofs)
[![Travis CI](https://api.travis-ci.org/centrifuge/precise-proofs.svg?branch=master)](https://travis-ci.org/centrifuge/precise-proofs)

Precise Proofs is a library for creating merlke proofs out of protobuf messages. It 
handles flattening of objects, ordering the fields by label and creating shareable and
independently verifiable proofs.

This library takes arbitrary protobuf messages and makes sure a merkle tree can be reliable calculated
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

## Proof format
This library defines a proof format that ensures both human readable, concise and secure merkle proofs:

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

There are a few things to note:
* When calculating the hash of the leaf, the dot notation of the property, the value and salt should
  be concatenated and separated by commas to produce the hash.
* The default proof expects values of documents to be salted to prevent rainbow table lookups.
* The value is included in the file as a string value not a native type. 


## Usage:

```go,
    // ExampleDocument is a protobuf message
    document := ExampleDocument{
        Value1: 1,
        ValueA: "Foo",
        ValueB: "Bar",
        ValueBytes1: []byte("foobar"),
    }

    // The FillSalts method is a helper function that fills all fields with 32 random bytes
    salts := SaltedExampleDocument{}
    preciseproofs.FillSalts(&salts)

    doctree := preciseproofs.NewDocumentTree()
    doctree.AddDocument(&document, &salts)
    fmt.Println("Merkle Root Hash", base64.StdEncoding.EncodeToString(doctree.RootHash))

    proof, _ := doctree.CreateProof("ValueA")

    proofJson, _ := json.Marshal(proof)

    fmt.Println("Proof:\n", string(proofJson))

    valid, _ := preciseproofs.ValidateProof(&proof, doctree.RootHash)

    fmt.Printf("Proof validated:", valid)
```

### Missing features

* Support for nested documents is in the works
* Currently only []byte, int64 and string types are supported 
* Custom hash functions, the hash function currently used is blake2b
