// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" // nolint:gosec
)

// deriveSessionKeys should be used in tests only.
// RFCs test vectors specifes derived keys to use,
// this struct is used to inject them into the cipher in tests.
type derivedSessionKeys struct {
	srtpSessionKey      []byte
	srtpSessionSalt     []byte
	srtpSessionAuthTag  []byte
	srtcpSessionKey     []byte
	srtcpSessionSalt    []byte
	srtcpSessionAuthTag []byte
}

func newSrtpCipherAesCmHmacSha1WithDerivedKeys(
	profile ProtectionProfile,
	keys derivedSessionKeys,
	encryptSRTP, encryptSRTCP bool,
) (*srtpCipherAesCmHmacSha1, error) {
	if profile == ProtectionProfileNullHmacSha1_80 || profile == ProtectionProfileNullHmacSha1_32 {
		encryptSRTP = false
		encryptSRTCP = false
	}

	srtpCipher := &srtpCipherAesCmHmacSha1{
		protectionProfileWithArgs: protectionProfileWithArgs{ProtectionProfile: profile},
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
	}

	var err error
	if srtpCipher.srtpBlock, err = aes.NewCipher(keys.srtpSessionKey); err != nil {
		return nil, err
	}

	if srtpCipher.srtcpBlock, err = aes.NewCipher(keys.srtcpSessionKey); err != nil {
		return nil, err
	}

	srtpCipher.srtpSessionSalt = keys.srtpSessionSalt
	srtpCipher.srtcpSessionSalt = keys.srtcpSessionSalt

	srtpCipher.srtcpSessionAuth = hmac.New(sha1.New, keys.srtcpSessionAuthTag)
	srtpCipher.srtpSessionAuth = hmac.New(sha1.New, keys.srtpSessionAuthTag)

	return srtpCipher, nil
}

func newSrtpCipherAeadAesGcmWithDerivedKeys(
	profile ProtectionProfile,
	keys derivedSessionKeys,
	encryptSRTP, encryptSRTCP bool,
) (*srtpCipherAeadAesGcm, error) {
	srtpCipher := &srtpCipherAeadAesGcm{
		protectionProfileWithArgs: protectionProfileWithArgs{ProtectionProfile: profile},
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
	}

	srtpBlock, err := aes.NewCipher(keys.srtpSessionKey)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtpCipher, err = cipher.NewGCM(srtpBlock)
	if err != nil {
		return nil, err
	}

	srtcpBlock, err := aes.NewCipher(keys.srtcpSessionKey)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtcpCipher, err = cipher.NewGCM(srtcpBlock)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtpSessionSalt = keys.srtpSessionSalt
	srtpCipher.srtcpSessionSalt = keys.srtcpSessionSalt

	return srtpCipher, nil
}

// createContextWithCipher creates a new SRTP Context with a pre-created cipher. This is used for testing purposes only.
func createContextWithCipher(profile ProtectionProfile, cipher srtpCipher) (*Context, error) {
	ctx := &Context{
		srtpSSRCStates:  map[uint32]*srtpSSRCState{},
		srtcpSSRCStates: map[uint32]*srtcpSSRCState{},
		profile:         profile,
		mkis:            map[string]srtpCipher{},
		cipher:          cipher,
	}
	err := SRTPNoReplayProtection()(ctx)
	if err != nil {
		return nil, err
	}
	err = SRTCPNoReplayProtection()(ctx)
	if err != nil {
		return nil, err
	}

	return ctx, nil
}
