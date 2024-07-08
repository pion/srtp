// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidSessionKeys_AesCm128(t *testing.T) {
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

	authKeyLen, err := ProtectionProfileAes128CmHmacSha1_80.AuthKeyLen()
	assert.NoError(t, err)

	sessionAuthTag, err := aesCmKeyDerivation(labelSRTPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		t.Errorf("generateSessionAuthTag failed: %v", err)
	} else if !bytes.Equal(sessionAuthTag, expectedSessionAuthTag) {
		t.Errorf("Session Auth Tag % 02x does not match expected % 02x", sessionAuthTag, expectedSessionAuthTag)
	}
}

func TestValidSessionKeys_AesCm256(t *testing.T) {
	masterKey := []byte{
		0xf0, 0xf0, 0x49, 0x14, 0xb5, 0x13, 0xf2, 0x76, 0x3a, 0x1b, 0x1f, 0xa1, 0x30, 0xf1, 0x0e, 0x29,
		0x98, 0xf6, 0xf6, 0xe4, 0x3e, 0x43, 0x09, 0xd1, 0xe6, 0x22, 0xa0, 0xe3, 0x32, 0xb9, 0xf1, 0xb6,
	}
	masterSalt := []byte{0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9, 0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2}

	expectedSessionKey := []byte{
		0x5b, 0xa1, 0x06, 0x4e, 0x30, 0xec, 0x51, 0x61, 0x3c, 0xad, 0x92, 0x6c, 0x5a, 0x28, 0xef, 0x73,
		0x1e, 0xc7, 0xfb, 0x39, 0x7f, 0x70, 0xa9, 0x60, 0x65, 0x3c, 0xaf, 0x06, 0x55, 0x4c, 0xd8, 0xc4,
	}
	expectedSessionSalt := []byte{0xfa, 0x31, 0x79, 0x16, 0x85, 0xca, 0x44, 0x4a, 0x9e, 0x07, 0xc6, 0xc6, 0x4e, 0x93}
	expectedSessionAuthTag := []byte{0xfd, 0x9c, 0x32, 0xd3, 0x9e, 0xd5, 0xfb, 0xb5, 0xa9, 0xdc, 0x96, 0xb3, 0x08, 0x18, 0x45, 0x4d, 0x13, 0x13, 0xdc, 0x05}

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

	authKeyLen, err := ProtectionProfileAes256CmHmacSha1_80.AuthKeyLen()
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

func BenchmarkGenerateCounter(b *testing.B) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	s := &srtpSSRCState{ssrc: 4160032510}

	srtpSessionSalt, err := aesCmKeyDerivation(labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt))
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		generateCounter(32846, uint32(s.index>>16), s.ssrc, srtpSessionSalt)
	}
}
