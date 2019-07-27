/* Package example contains a code sample to explain usage and sample data for tests.
 */
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/centrifuge/precise-proofs/proofs"
	"golang.org/x/crypto/blake2b"
)

func main() {
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
		PaddingA: "WillBePadded",
	}

	blake2b256, err := blake2b.New256([]byte{1, 2, 3, 4})
	checkErr(err)

	doctree, err := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New(), LeafHash: blake2b256})
	checkErr(err)

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
	doctree2, err := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New(), LeafHash: blake2b256, TreeDepth: 5})
	checkErr(err)
	fmt.Printf("\n\nNon empty leaves number of generated tree should be 13\n")
	checkErr(doctree2.AddLeavesFromDocument(&document))
	checkErr(doctree2.Generate())
	fmt.Printf("Non empty leaves number of the tree is %d\n", len(doctree2.GetLeaves()))

	// Generate the actual proof for a field. In this case the field called "ValueA".
	proof, err = doctree2.CreateProof("valueA")
	checkErr(err)
	proofJson, _ = json.Marshal(proof)
	fmt.Println("Proof:\n", string(proofJson))

	// Validate the proof that was just generated
	valid, err = doctree2.ValidateProof(&proof)
	checkErr(err)

	fmt.Printf("Proof validated: %v\n", valid)

}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
