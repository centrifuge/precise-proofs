package tools

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	proofspb "github.com/centrifuge/precise-proofs/proofs/proto"
)

// ConvertJSONProofs converts json string to []proto.Proof
func ConvertJSONProofs(jsonProof string) ([]*proofspb.Proof, []byte, error) {
	type header struct {
		DocumentRoot string `json:"document_root"`
	}
	type proofItem struct {
		Property string `json:"property"`
		Value string `json:"value"`
		Salt string `json:"salt"`
		Hash string `json:"hash"`
		SortedHashes []string `json:"sorted_hashes"`
	}
	type proofPayload struct {
		Header header `json:"header"`
		FieldProofs []proofItem `json:"field_proofs"`
	}
	parsed := &proofPayload{}
	err := json.Unmarshal([]byte(jsonProof), parsed)
	if err != nil {
		return nil, nil, err
	}
	docRoot, err := hex.DecodeString(strings.Replace(parsed.Header.DocumentRoot, "0x", "", -1))
	if err != nil {
		return nil, nil, err
	}
	converted := make([]*proofspb.Proof, len(parsed.FieldProofs))
	for idx, item := range parsed.FieldProofs {
		property, err := hex.DecodeString(strings.Replace(item.Property,"0x", "", -1))
		if err != nil {
			return nil, nil, err
		}
		value, err := hex.DecodeString(strings.Replace(item.Value,"0x", "", -1))
		if err != nil {
			return nil, nil, err
		}
		salt, err := hex.DecodeString(strings.Replace(item.Salt,"0x", "", -1))
		if err != nil {
			return nil, nil, err
		}
		hashItem, err := hex.DecodeString(strings.Replace(item.Hash,"0x", "", -1))
		if err != nil {
			return nil, nil, err
		}
		shb := make([][]byte, len(item.SortedHashes))
		for idy, sh := range item.SortedHashes {
			shh, err := hex.DecodeString(strings.Replace(sh,"0x", "", -1))
			if err != nil {
				return nil, nil, err
			}
			shb[idy] = shh
		}
		converted[idx] = &proofspb.Proof{
			Property:     &proofspb.Proof_CompactName{CompactName: property},
			Value:        value,
			Salt:         salt,
			Hash:         hashItem,
			SortedHashes: shb,
		}
	}

	return converted, docRoot, err
}

