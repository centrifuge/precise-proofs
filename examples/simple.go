/* Package example contains a code sample to explain usage and sample data for tests.
 */
package main

import (
	"encoding/json"
	"fmt"
	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/centrifuge/precise-proofs/proofs"
	"crypto/sha256"
)

func printError(err error){
	if err != nil{
		fmt.Printf("There was an error: [%v]\n", err)
	}
}

func main () {
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
	proofs.FillSalts(&salts)

	doctree := proofs.NewDocumentTree()

	//Setting the desired hash function that is used to generate the tree
	sha256Hash := sha256.New()
	doctree.SetHashFunc(sha256Hash)

	err := doctree.FillTree(&document, &salts)
	printError(err)
	fmt.Printf("Generated tree: %s\n", doctree.String())

	// Generate the actual proof for a field. In this case the field called "ValueA".
	proof, err := doctree.CreateProof("valueA")
	printError(err)
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	// Validate the proof that was just generated
	valid, err := doctree.ValidateProof(&proof)
	printError(err)

	fmt.Printf("Proof validated: %v\n", valid)
}
