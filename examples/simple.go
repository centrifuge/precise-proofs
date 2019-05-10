/* Package example contains a code sample to explain usage and sample data for tests.
 */
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/centrifuge/precise-proofs/proofs"
)

func main() {
	// ExampleDocument is a protobuf message
	document := documentspb.ExampleDocument{
		Value1:      1,
		ValueA:      "Foo",
		ValueB:      "Bar",
		ValueBytes1: []byte("foobar"),
		PaddingA:    "WillBePadded",
	}

	doctree := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New()})

	checkErr(doctree.AddLeavesFromDocument(&document))
	checkErr(doctree.Generate())
	fmt.Printf("Generated tree: %s\n", doctree.String())

	// Generate the actual proof for a field. In this case the field called "ValueA".
	proof, err := doctree.CreateProof("valueA")
	checkErr(err)
	proofJson, _ := json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	// Validate the proof that was just generated
	valid, err := doctree.ValidateProof(&proof)
	checkErr(err)

	fmt.Printf("Proof validated: %v\n", valid)

	// Fixed Length Tree
	doctree2 := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New(), TreeDepth: 5})
	fmt.Printf("\n\nLeaves number of generated tree should be %d\n", 1<<5)
	checkErr(doctree2.AddLeavesFromDocument(&document))
	checkErr(doctree2.Generate())
	fmt.Printf("Leaves number of the tree is %d\n", len(doctree2.GetLeaves()))

}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
