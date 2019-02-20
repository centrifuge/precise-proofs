package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall/js"

	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/centrifuge/precise-proofs/proofs"
	"github.com/centrifuge/precise-proofs/proofs/proto"
	"github.com/golang/protobuf/jsonpb"
)

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func generateProof(i []js.Value) {
	var document documentspb.ExampleDocument
	fmt.Printf("JSON : %s\n", i[0].String())
	err := jsonpb.Unmarshal(strings.NewReader(i[0].String()), &document)
	checkErr(err)

	salts := proofs.Salts{}
	doctree := proofs.NewDocumentTree(proofs.TreeOptions{Hash: sha256.New(), Salts: &salts})

	checkErr(doctree.AddLeavesFromDocument(&document))
	checkErr(doctree.Generate())
	fmt.Printf("Generated tree: %s\n", doctree.String())

	//Generate the actual proof for a field. In this case the field called "ValueA".
	proof, err := doctree.CreateProof("enum_type")
	checkErr(err)
	m := jsonpb.Marshaler{}
	proofJson, _ := m.MarshalToString(&proof)
	fmt.Println("Proof JSON:\n", string(proofJson))

	// Validate the proof that was just generated
	valid, err := doctree.ValidateProof(&proof)
	checkErr(err)

	fmt.Printf("Proof validated: %v\n", valid)
}

func validateProof(i []js.Value) {
	proof := &proofspb.Proof{
		Property: proofs.ReadableName("enum_type"),
	}
	fmt.Printf("JSON : %s\n", i[0].String())
	fmt.Printf("RootHash : %s\n", i[1].String())
	err := jsonpb.Unmarshal(strings.NewReader(i[0].String()), proof)
	checkErr(err)
	fmt.Println("Proof: \n", proof)

	rootHash, err := hex.DecodeString(i[1].String())
	checkErr(err)

	doctree := proofs.NewDocumentTreeWithRootHash(rootHash, sha256.New())
	fmt.Printf("Generated tree: %s\n", doctree.String())

	// Validate the proof that was just generated
	valid, err := doctree.ValidateProof(proof)
	checkErr(err)

	fmt.Printf("Proof validated: %v\n", valid)
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
