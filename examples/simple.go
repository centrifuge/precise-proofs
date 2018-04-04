/* Package example contains a code sample to explain usage and sample data for tests.
 */
package main

import (
	"github.com/centrifuge/precise-proofs/proofs"
	"fmt"
	"encoding/json"
	"github.com/centrifuge/precise-proofs/examples/documents"
)

func main () {
	// ExampleDocument is a protobuf message
	document := documents.ExampleDocument{
		Value1: 1,
		ValueA: "Foo",
		ValueB: "Bar",
		ValueBytes1: []byte("foobar"),
	}

	// The FillSalts method is a helper function that fills all fields with 32
	// random bytes. SaltedExampleDocument is a protobuf message that has the
	// same structure as ExampleDocument but has all `bytes` field types.
	salts := documents.SaltedExampleDocument{}
	proofs.FillSalts(&salts)

	doctree := proofs.NewDocumentTree()
	doctree.FillTree(&document, &salts)
	fmt.Printf("Generated tree: %s\n", doctree.String())

	proof, _ := doctree.CreateProof("ValueA")
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	valid, _ := doctree.ValidateProof(&proof)

	fmt.Printf("Proof validated: %v\n", valid)
}
