package proofs

import (
	"testing"

	"github.com/centrifuge/precise-proofs/examples/documents"
	"github.com/stretchr/testify/assert"
)

func TestFillSalts(t *testing.T) {
	// Fill a properly formatted one level document
	exampleDoc := &documentspb.ExampleDocument{}
	exampleSalts := &documentspb.SaltedExampleDocument{}
	err := FillSalts(exampleDoc, exampleSalts)
	assert.Nil(t, err, "Fill salts should not fail")

	assert.NotNil(t, exampleSalts.ValueA)

	// Document with repeated fields
	exampleFRDoc := &documentspb.ExampleFilledRepeatedDocument
	exampleFRSalts := &documentspb.SaltedSimpleRepeatedDocument{}
	err = FillSalts(exampleFRDoc, exampleFRSalts)
	assert.Nil(t, err, "Fill salts should not fail")
	assert.NotNil(t, exampleFRSalts.ValueCLength)

	assert.Equal(t, len(exampleFRDoc.ValueC), len(exampleFRSalts.ValueC))
	assert.NotNil(t, exampleFRSalts.ValueC[0])

	// Document with nested and repeated fields
	exampleFNDoc := &documentspb.ExampleFilledNestedRepeatedDocument
	exampleFNSalts := &documentspb.SaltedNestedRepeatedDocument{}
	err = FillSalts(exampleFNDoc, exampleFNSalts)
	assert.Nil(t, err, "Fill salts should not fail")

	assert.Equal(t, len(exampleFNDoc.ValueC), len(exampleFNSalts.ValueC))
	assert.NotNil(t, exampleFNSalts.ValueC[0].ValueA)
	assert.NotNil(t, exampleFNSalts.ValueD.ValueA.ValueA)

	// Document with two level repeated fields
	exampleFTRDoc := &documentspb.ExampleFilledTwoLevelRepeatedDocument
	exampleFTRSalts := &documentspb.SaltedTwoLevelRepeatedDocument{}
	err = FillSalts(exampleFTRDoc, exampleFTRSalts)
	assert.Nil(t, err, "Fill salts should not fail")

	assert.NotNil(t, exampleFTRSalts.ValueBLength)
	assert.NotNil(t, exampleFTRSalts.ValueB[0].ValueALength)

	// Salt Document with not []byte fields
	badExample := &documentspb.ExampleDocument{}
	err = FillSalts(badExample, badExample)
	assert.NotNil(t, err, "Fill salts should error because of string")
}
