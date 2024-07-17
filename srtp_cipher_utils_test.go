// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" // nolint:gosec
)

// deriveSessionKeys should be used in tests only. RFCs test vectors specifes derived keys to use, this struct is used to inject them into the cipher in tests.
type derivedSessionKeys struct {
	srtpSessionKey      []byte
	srtpSessionSalt     []byte
	srtpSessionAuthTag  []byte
	srtcpSessionKey     []byte
	srtcpSessionSalt    []byte
	srtcpSessionAuthTag []byte
}

func newSrtpCipherAesCmHmacSha1WithDerivedKeys(profile ProtectionProfile, keys derivedSessionKeys, encryptSRTP, encryptSRTCP bool) (*srtpCipherAesCmHmacSha1, error) {
	if profile == ProtectionProfileNullHmacSha1_80 || profile == ProtectionProfileNullHmacSha1_32 {
		encryptSRTP = false
		encryptSRTCP = false
	}

	s := &srtpCipherAesCmHmacSha1{
		ProtectionProfile: profile,
		srtpEncrypted:     encryptSRTP,
		srtcpEncrypted:    encryptSRTCP,
	}

	var err error
	if s.srtpBlock, err = aes.NewCipher(keys.srtpSessionKey); err != nil {
		return nil, err
	}

	if s.srtcpBlock, err = aes.NewCipher(keys.srtcpSessionKey); err != nil {
		return nil, err
	}

	s.srtpSessionSalt = keys.srtpSessionSalt
	s.srtcpSessionSalt = keys.srtcpSessionSalt

	s.srtcpSessionAuth = hmac.New(sha1.New, keys.srtcpSessionAuthTag)
	s.srtpSessionAuth = hmac.New(sha1.New, keys.srtpSessionAuthTag)

	return s, nil
}

func newSrtpCipherAeadAesGcmWithDerivedKeys(profile ProtectionProfile, keys derivedSessionKeys, encryptSRTP, encryptSRTCP bool) (*srtpCipherAeadAesGcm, error) {
	s := &srtpCipherAeadAesGcm{ProtectionProfile: profile, srtpEncrypted: encryptSRTP, srtcpEncrypted: encryptSRTCP}

	srtpBlock, err := aes.NewCipher(keys.srtpSessionKey)
	if err != nil {
		return nil, err
	}

	s.srtpCipher, err = cipher.NewGCM(srtpBlock)
	if err != nil {
		return nil, err
	}

	srtcpBlock, err := aes.NewCipher(keys.srtcpSessionKey)
	if err != nil {
		return nil, err
	}

	s.srtcpCipher, err = cipher.NewGCM(srtcpBlock)
	if err != nil {
		return nil, err
	}

	s.srtpSessionSalt = keys.srtpSessionSalt
	s.srtcpSessionSalt = keys.srtcpSessionSalt

	return s, nil
}

// createContextWithCipher creates a new SRTP Context with a pre-created cipher. This is used for testing purposes only.
func createContextWithCipher(profile ProtectionProfile, cipher srtpCipher) (*Context, error) {
	c := &Context{
		srtpSSRCStates:  map[uint32]*srtpSSRCState{},
		srtcpSSRCStates: map[uint32]*srtcpSSRCState{},
		profile:         profile,
		mkis:            map[string]srtpCipher{},
		cipher:          cipher,
	}
	err := SRTPNoReplayProtection()(c)
	if err != nil {
		return nil, err
	}
	err = SRTCPNoReplayProtection()(c)
	if err != nil {
		return nil, err
	}
	return c, nil
}
