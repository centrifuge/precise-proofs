/* Package example contains a code sample to explain usage and sample data for tests.
 */
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/centrifuge/precise-proofs/proofs"
	"github.com/centrifuge/precise-proofs/proofs/proto"
)

func main() {
	// ContainSalts is a protobuf message which contain salts message
	document := documentspb.ContainSalts{
		ValueA:     "valueAValue",
		ValueB:     10,
		Salts:      []*proofspb.Salt{{Compact: []byte{0,0,0,1}, Value: []byte{0x1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x2}},{Compact: []byte{0,0,0,2}, Value: []byte{0x3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x4}}},
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
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
