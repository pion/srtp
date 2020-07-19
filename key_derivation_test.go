package srtp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidSessionKeys(t *testing.T) {
	masterKey := []byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39}
	masterSalt := []byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6}

	expectedSessionKey := []byte{0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, 0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7, 0xA0, 0x87}
	expectedSessionSalt := []byte{0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C, 0x85, 0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1}
	expectedSessionAuthTag := []byte{0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, 0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25, 0x6A, 0x15, 0x6D, 0x38, 0xBA, 0xA4}

	sessionKey, err := aesCmKeyDerivation(labelSRTPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		t.Errorf("generateSessionKey failed: %v", err)
	} else if !bytes.Equal(sessionKey, expectedSessionKey) {
		t.Errorf("Session Key % 02x does not match expected % 02x", sessionKey, expectedSessionKey)
	}

	sessionSalt, err := aesCmKeyDerivation(labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt))
	if err != nil {
		t.Errorf("generateSessionSalt failed: %v", err)
	} else if !bytes.Equal(sessionSalt, expectedSessionSalt) {
		t.Errorf("Session Salt % 02x does not match expected % 02x", sessionSalt, expectedSessionSalt)
	}

	authKeyLen, err := ProtectionProfileAes128CmHmacSha1_80.authKeyLen()
	assert.NoError(t, err)

	sessionAuthTag, err := aesCmKeyDerivation(labelSRTPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		t.Errorf("generateSessionAuthTag failed: %v", err)
	} else if !bytes.Equal(sessionAuthTag, expectedSessionAuthTag) {
		t.Errorf("Session Auth Tag % 02x does not match expected % 02x", sessionAuthTag, expectedSessionAuthTag)
	}
}

// This test asserts that calling aesCmKeyDerivation with a non-zero indexOverKdr fails
// Currently this isn't supported, but the API makes sure we can add this in the future
func TestIndexOverKDR(t *testing.T) {
	_, err := aesCmKeyDerivation(labelSRTPAuthenticationTag, []byte{}, []byte{}, 1, 0)
	assert.Error(t, err)
}
