Precise Proofs
==============
Precise Proofs is a library for creating merlke proofs out of protobuf messages. It 
handles flattening of objects, ordering the fields by label and creating shareable and
independently verifiable proofs.

## Usage:

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


### Missing features

* Support for nested documents is in the works
* Currently only []byte, int64 and string types are supported 
