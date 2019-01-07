package proofspb

import (
	"fmt"
)

// PropertyName is a []byte-convertible name of a Property. A PropertyName can be extracted from a Property using a compact or human-readable encoding
type PropertyName isProof_Property

func (pn *Proof_ReadableName) String() string {
	return pn.ReadableName
}

func (pn *Proof_CompactName) String() string {
	return fmt.Sprint(pn.CompactName)
}
