// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContextROC(t *testing.T) {
	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR)
	assert.NoError(t, err)

	_, ok := c.ROC(123)
	assert.False(t, ok, "ROC must return false for unused SSRC")

	c.SetROC(123, 100)
	roc, ok := c.ROC(123)
	assert.True(t, ok, "ROC must return true for used SSRC")
	assert.Equal(t, roc, uint32(100))
}

func TestContextIndex(t *testing.T) {
	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR)
	assert.NoError(t, err)

	_, ok := c.Index(123)
	assert.False(t, ok, "Index must return false for unused SSRC")

	c.SetIndex(123, 100)
	index, ok := c.Index(123)
	assert.True(t, ok, "Index must return true for used SSRC")
	assert.Equal(t, index, uint32(100))
}

func TestContextWithoutMKI(t *testing.T) {
	ctx, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR)
	assert.NoError(t, err)

	err = ctx.AddCipherForMKI(nil, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = ctx.AddCipherForMKI(make([]byte, 0), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = ctx.AddCipherForMKI(make([]byte, 4), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = ctx.SetSendMKI(nil)
	assert.Error(t, err)

	err = ctx.SetSendMKI(make([]byte, 0))
	assert.Error(t, err)

	err = ctx.RemoveMKI(nil)
	assert.Error(t, err)

	err = ctx.RemoveMKI(make([]byte, 0))
	assert.Error(t, err)

	err = ctx.RemoveMKI(make([]byte, 2))
	assert.Error(t, err)
}

func TestAddMKIToContextWithMKI(t *testing.T) {
	mki1 := []byte{1, 2, 3, 4}
	mki2 := []byte{2, 3, 4, 5}

	ctx, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	err = ctx.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	assert.NoError(t, err)

	err = ctx.AddCipherForMKI(nil, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = ctx.AddCipherForMKI(make([]byte, 0), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = ctx.AddCipherForMKI(make([]byte, 3), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = ctx.AddCipherForMKI(mki1, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = ctx.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)
}

func TestContextSetSendMKI(t *testing.T) {
	mki1 := []byte{1, 2, 3, 4}
	mki2 := []byte{2, 3, 4, 5}

	ctx, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	err = ctx.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	assert.NoError(t, err)

	err = ctx.SetSendMKI(mki1)
	assert.NoError(t, err)

	err = ctx.SetSendMKI(mki2)
	assert.NoError(t, err)

	err = ctx.SetSendMKI(make([]byte, 4))
	assert.Error(t, err)
}

func TestContextRemoveMKI(t *testing.T) {
	mki1 := []byte{1, 2, 3, 4}
	mki2 := []byte{2, 3, 4, 5}
	mki3 := []byte{3, 4, 5, 6}

	ctx, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	err = ctx.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	assert.NoError(t, err)

	err = ctx.AddCipherForMKI(mki3, make([]byte, 16), make([]byte, 14))
	assert.NoError(t, err)

	err = ctx.RemoveMKI(make([]byte, 4))
	assert.Error(t, err)

	err = ctx.RemoveMKI(mki1)
	assert.Error(t, err)

	err = ctx.SetSendMKI(mki3)
	assert.NoError(t, err)

	err = ctx.RemoveMKI(mki1)
	assert.NoError(t, err)

	err = ctx.RemoveMKI(mki2)
	assert.NoError(t, err)

	err = ctx.RemoveMKI(mki3)
	assert.Error(t, err)
}

func TestInvalidContextOptions(t *testing.T) {
	profiles := []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileNullHmacSha1_80,
		ProtectionProfileNullHmacSha1_32,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	}

	for _, profile := range profiles {
		t.Run(profile.String(), func(t *testing.T) {
			keyLen, err := profile.KeyLen()
			assert.NoError(t, err)
			saltLen, err := profile.SaltLen()
			assert.NoError(t, err)
			authTagLen, err := profile.AuthTagRTPLen()
			assert.NoError(t, err)
			authKeyLen, err := profile.AuthKeyLen()
			assert.NoError(t, err)

			masterKey := make([]byte, keyLen)
			masterSalt := make([]byte, saltLen)
			aeadAuthTagLen, err := profile.AEADAuthTagLen()
			assert.NoError(t, err)

			t.Run("InvalidRCCContextOptions", func(t *testing.T) {
				authTagLenOpt := SRTPAuthenticationTagLength(authTagLen)

				_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode1, 0),
					authTagLenOpt)
				assert.ErrorIs(t, err, errZeroRocTransmitRate)
				_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode2, 0),
					authTagLenOpt)
				assert.ErrorIs(t, err, errZeroRocTransmitRate)
				_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode3, 0),
					authTagLenOpt)
				assert.ErrorIs(t, err, errZeroRocTransmitRate)

				_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode1, 10),
					authTagLenOpt)
				assert.ErrorIs(t, err, errUnsupportedRccMode)
				if aeadAuthTagLen == 0 { // AES-CM
					_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode3, 10),
						authTagLenOpt)
					assert.ErrorIs(t, err, errUnsupportedRccMode)

					if authTagLen == 4 {
						_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode2, 10))
						assert.ErrorIs(t, err, errTooShortSRTPAuthTag)
					}

					for n := 0; n < 4; n++ {
						_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode2, 10),
							SRTPAuthenticationTagLength(n))
						assert.ErrorIs(t, err, errTooShortSRTPAuthTag)
					}
				} else { // AEAD
					_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode2, 10),
						authTagLenOpt)
					assert.ErrorIs(t, err, errUnsupportedRccMode)
				}
			})

			t.Run("InvalidSRTPAuthTagLen", func(t *testing.T) {
				_, err = CreateContext(masterKey, masterSalt, profile, SRTPAuthenticationTagLength(authKeyLen+1))
				assert.ErrorIs(t, err, errTooLongSRTPAuthTag)
			})
		})
	}
}
