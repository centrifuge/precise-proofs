package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertJSONProofs(t *testing.T) {
	// wrong JSON payload format
	_, _, err := ConvertJSONProofs("")
	assert.Error(t, err)

	// docroot wrong hex format
	payload := `
{
	"header": {
    "document_root":"wronghex"
  },
  "field_proofs": [
	]
}
`
	_, _, err = ConvertJSONProofs(payload)
	assert.Error(t, err)

	// property wrong hex format
	payload = `
{
	"header": {
    "document_root":"0x7eba2627f27e0c2b49cd7f3aee6a11ca2637e1e07d5bb82b68253e7905ca074c"
  },
  "field_proofs": [
    {
      "property": "wronghex",
      "value": "0x007b0000000000000000",
      "salt": "0x3d9f77a675dbc27641b27d8bbf612164774adc814a40d3c1324c5c77b26f9aa2",
      "hash": "0x",
      "sorted_hashes": [
        "0xd42948fa37dd912117ac5966b55d4b364005e4dc366e3afb6caf38649dce7d20",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    }
	]
}
`
	_, _, err = ConvertJSONProofs(payload)
	assert.Error(t, err)

	// value wrong hex format
	payload = `
{
	"header": {
    "document_root":"0x7eba2627f27e0c2b49cd7f3aee6a11ca2637e1e07d5bb82b68253e7905ca074c"
  },
  "field_proofs": [
    {
      "property": "0x000100000000000e",
      "value": "wronghex",
      "salt": "0x3d9f77a675dbc27641b27d8bbf612164774adc814a40d3c1324c5c77b26f9aa2",
      "hash": "0x",
      "sorted_hashes": [
        "0xd42948fa37dd912117ac5966b55d4b364005e4dc366e3afb6caf38649dce7d20",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    }
	]
}
`
	_, _, err = ConvertJSONProofs(payload)
	assert.Error(t, err)

	// salt wrong hex format
	payload = `
{
	"header": {
    "document_root":"0x7eba2627f27e0c2b49cd7f3aee6a11ca2637e1e07d5bb82b68253e7905ca074c"
  },
  "field_proofs": [
    {
      "property": "0x000100000000000e",
      "value": "0x007b0000000000000000",
      "salt": "wronghex",
      "hash": "0x",
      "sorted_hashes": [
        "0xd42948fa37dd912117ac5966b55d4b364005e4dc366e3afb6caf38649dce7d20",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    }
	]
}
`
	_, _, err = ConvertJSONProofs(payload)
	assert.Error(t, err)

	// hash wrong hex format
	payload = `
{
	"header": {
    "document_root":"0x7eba2627f27e0c2b49cd7f3aee6a11ca2637e1e07d5bb82b68253e7905ca074c"
  },
  "field_proofs": [
    {
      "property": "0x000100000000000e",
      "value": "0x007b0000000000000000",
      "salt": "0x3d9f77a675dbc27641b27d8bbf612164774adc814a40d3c1324c5c77b26f9aa2",
      "hash": "wronghex",
      "sorted_hashes": [
        "0xd42948fa37dd912117ac5966b55d4b364005e4dc366e3afb6caf38649dce7d20",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    }
	]
}
`
	_, _, err = ConvertJSONProofs(payload)
	assert.Error(t, err)

	// sortedhashes wrong hex format
	payload = `
{
	"header": {
    "document_root":"0x7eba2627f27e0c2b49cd7f3aee6a11ca2637e1e07d5bb82b68253e7905ca074c"
  },
  "field_proofs": [
    {
      "property": "0x000100000000000e",
      "value": "0x007b0000000000000000",
      "salt": "0x3d9f77a675dbc27641b27d8bbf612164774adc814a40d3c1324c5c77b26f9aa2",
      "hash": "0x",
      "sorted_hashes": [
        "wronghex",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    }
	]
}
`
	_, _, err = ConvertJSONProofs(payload)
	assert.Error(t, err)

	// success
	payload = `
{
	"header": {
    "document_root":"0x7eba2627f27e0c2b49cd7f3aee6a11ca2637e1e07d5bb82b68253e7905ca074c"
  },
  "field_proofs": [
    {
      "property": "0x000100000000000e",
      "value": "0x007b0000000000000000",
      "salt": "0x3d9f77a675dbc27641b27d8bbf612164774adc814a40d3c1324c5c77b26f9aa2",
      "hash": "0x",
      "sorted_hashes": [
        "0xd42948fa37dd912117ac5966b55d4b364005e4dc366e3afb6caf38649dce7d20",
        "0xccaad8761ce1a541483d2fb98d621a9a9c11d7b03d82fdbeb2cefdbb8405916e",
        "0x598e8661d6c2a206e632f12c9031a3b50e02af430b144f71db2bbde83e8da2ec",
				"0x7f8410d0adbc62a9b9933c8cb16a45c0cca73dec62e89b185f22a06073e7b960",
				"0x6a37a214f9f3cb50f0cbdfd4183040781860acf7ccb1a4c8453cf31003fc99e7",
				"0x41337de1d0f1a323f5fcca15144b7a1f37cbb442a053fee73f84f27afbc3d719",
				"0x480d3bf285726b8ecf2199da06f35bb77830e07828e036bf9a8dc8c95129f45e",
				"0xa42cfcb21740fbd16b4a48499f7d273611fa413b001f9f0fb476eb00d85b5eeb"
      ]
    }
	]
}
`
	pfs, dr, err := ConvertJSONProofs(payload)
	assert.NoError(t, err)
	assert.Len(t, pfs, 1)
	assert.Len(t, dr, 32)
}

