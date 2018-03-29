/* Package example contains a code sample to explain usage and sample data for tests.
 */
package example

import (
	"github.com/centrifuge/precise-proofs/preciseproofs"
	"fmt"
	"encoding/json"
	"encoding/base64"
	"github.com/centrifuge/precise-proofs/example/documents"
)

func main () {

	// ExampleDocument is a protobuf message
	document := documents.ExampleDocument{
		Value1: 1,
		ValueA: "Foo",
		ValueB: "Bar",
		ValueBytes1: []byte("foobar"),
	}

	// The FillSalts method is a helper function that fills all fields with 32 random bytes
	salts := documents.SaltedExampleDocument{}
	preciseproofs.FillSalts(&salts)

	doctree := preciseproofs.NewDocumentTree()
	doctree.AddDocument(&document, &salts)
	fmt.Println("Merkle Root Hash", base64.StdEncoding.EncodeToString(doctree.RootHash))

	proof, _ := doctree.CreateProof("ValueA")

	proofJson, _ := json.Marshal(proof)

	fmt.Println("Proof:\n", string(proofJson))

	valid, _ := doctree.ValidateProof(&proof)

	fmt.Printf("Proof validated:", valid)
}
