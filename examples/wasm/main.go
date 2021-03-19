// +build wasm

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall/js"

	documentspb "github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/centrifuge/precise-proofs/proofs"
	proofspb "github.com/centrifuge/precise-proofs/proofs/proto"
	"github.com/golang/protobuf/jsonpb"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// Generate Proof from sample Document JSON for given Field Name input
func generateProof(i []js.Value) {
	var document documentspb.ExampleDocument
	fmt.Printf("JSON : %s\n", i[0].String())
	err := jsonpb.Unmarshal(strings.NewReader(i[0].String()), &document)
	checkErr(err)

	doctree, err := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New()})
	checkErr(err)

	checkErr(doctree.AddLeavesFromDocument(&document))
	checkErr(doctree.Generate())
	fmt.Printf("Generated tree: %s\n", doctree.String())

	// Generate the actual proof for a field. In this case the field called "ValueA".
	proof, err := doctree.CreateProof(i[1].String())
	checkErr(err)
	m := jsonpb.Marshaler{}
	proofJson, _ := m.MarshalToString(&proof)
	fmt.Println("Proof JSON:\n", string(proofJson))

	js.Global().Get("document").Call("getElementById", "resultRootHash").Set("value", hex.EncodeToString(doctree.RootHash()))
	js.Global().Get("document").Call("getElementById", "resultProof").Set("value", string(proofJson))
}

// Validate generated Proof matches given RootHash
func validateProof(i []js.Value) {
	fmt.Printf("JSON : %s\n", i[0].String())
	fmt.Printf("RootHash : %s\n", i[1].String())
	fmt.Printf("ReadableName : %s\n", i[2].String())

	proof := &proofspb.Proof{
		Property: proofs.ReadableName(i[2].String()),
	}

	err := jsonpb.Unmarshal(strings.NewReader(i[0].String()), proof)
	checkErr(err)
	fmt.Println("Proof: \n", proof)

	rootHash, err := hex.DecodeString(i[1].String())
	checkErr(err)

	doctree, err := proofs.NewDocumentTreeWithRootHash(proofs.TreeOptions{Hash: sha256.New()}, rootHash)
	checkErr(err)
	fmt.Printf("Generated tree: %s\n", doctree.String())

	// Validate the proof that was just generated
	valid, err := doctree.ValidateProof(proof)
	checkErr(err)

	fmt.Printf("Proof validated: %v\n", valid)

	js.Global().Get("document").Call("getElementById", "resultValidProof").Set("value", "Valid: "+fmt.Sprint(valid))
}

func registerCallbacks() {
	js.Global().Set("generateProof", js.NewCallback(generateProof))
	js.Global().Set("validateProof", js.NewCallback(validateProof))
}

func main() {
	c := make(chan struct{}, 0)

	println("WASM Go Initialized")

	// register functions
	registerCallbacks()
	<-c
}
