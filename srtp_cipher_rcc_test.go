// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

// Tests for Roll-over Counter Carrying Transform from RFC 4771

// nolint:cyclop
func TestRCC(t *testing.T) {
	const (
		ROC             = uint32(0x12345678)
		SSRC            = uint32(0xcafebabe)
		ROCTransmitRate = uint16(10)
	)

	MKI := []byte{0x05, 0x06, 0x07, 0x08}

	decryptedRTPPacket := []byte{
		0x80, 0x0f, 0x00, 0x00, 0xde, 0xca, 0xfb, 0xad,
		0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab,
	}

	// Test all combinations of profiles, MKI enabled/disabled and RTP encryption enabled/disabled
	profiles := []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	}
	useMkiInTest := map[string]bool{
		"NoMKI": false,
		"MKI":   true,
	}
	useRTPEncryption := map[string]bool{
		"Encrypt": false,
		"NULL":    true,
	}
	for _, profile := range profiles {
		for useMkiName, useMki := range useMkiInTest {
			for rtpEncryptName, rtpEncrypt := range useRTPEncryption {
				t.Run(fmt.Sprintf("%s-%s-%s", profile.String(), useMkiName, rtpEncryptName), func(t *testing.T) {
					keyLen, err := profile.KeyLen()
					assert.NoError(t, err)
					saltLen, err := profile.SaltLen()
					assert.NoError(t, err)
					authTagLen, err := profile.AuthTagRTPLen()
					assert.NoError(t, err)
					aeadAuthTagLen, err := profile.AEADAuthTagLen()
					assert.NoError(t, err)

					masterKey := make([]byte, keyLen)
					masterSalt := make([]byte, saltLen)

					rccMode := RCCMode2
					if aeadAuthTagLen != 0 {
						rccMode = RCCMode3
					}
					optsRCC := []ContextOption{RolloverCounterCarryingTransform(rccMode, ROCTransmitRate)}
					var optsNoRCC []ContextOption
					if useMki {
						optsRCC = append(optsRCC, MasterKeyIndicator(MKI))
						optsNoRCC = append(optsNoRCC, MasterKeyIndicator(MKI))
					}
					if !rtpEncrypt {
						optsRCC = append(optsRCC, SRTPNoEncryption())
						optsNoRCC = append(optsNoRCC, SRTPNoEncryption())
					}

					t.Run("CheckEncryptDecryptRTPPacketsWithROC", func(t *testing.T) {
						ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
						assert.NoError(t, err)
						ctxEnc.SetROC(SSRC, ROC)

						ctxEncNoRCC, err := CreateContext(masterKey, masterSalt, profile, optsNoRCC...)
						assert.NoError(t, err)
						ctxEncNoRCC.SetROC(SSRC, ROC)

						ctxDec, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
						assert.NoError(t, err)

						rtpPacket := slices.Clone(decryptedRTPPacket)
						var header rtp.Header
						_, err = header.Unmarshal(rtpPacket)
						assert.NoError(t, err)
						header.SequenceNumber = 0
						_, err = header.MarshalTo(rtpPacket)
						assert.NoError(t, err)

						srtpPacketWithROC, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
						assert.NoError(t, err)

						srtpPacketWithoutROC, err := ctxEncNoRCC.EncryptRTP(nil, rtpPacket, nil)
						assert.NoError(t, err)

						pktLen := len(srtpPacketWithROC)
						if aeadAuthTagLen == 0 {
							// AES-CM - ROC is at the beginning of the auth tag, which is shifted and truncated by 4 bytes
							assert.Equal(t, pktLen, len(srtpPacketWithoutROC))
							assert.Equal(t, ROC, binary.BigEndian.Uint32(srtpPacketWithROC[pktLen-authTagLen:]))
							assert.Equal(t, srtpPacketWithROC[:pktLen-authTagLen], srtpPacketWithoutROC[:pktLen-authTagLen])
							assert.Equal(t, srtpPacketWithROC[pktLen-authTagLen+4:], srtpPacketWithoutROC[pktLen-authTagLen:pktLen-4])
						} else {
							// AEAD - ROC is appended at the end of the packet
							assert.Equal(t, pktLen-4, len(srtpPacketWithoutROC))
							assert.Equal(t, ROC, binary.BigEndian.Uint32(srtpPacketWithROC[pktLen-4:]))
							assert.Equal(t, srtpPacketWithROC[:pktLen-4], srtpPacketWithoutROC)
						}

						decrypted, err := ctxDec.DecryptRTP(nil, srtpPacketWithROC, nil)
						assert.NoError(t, err)
						assert.Equal(t, rtpPacket, decrypted)
					})

					t.Run("CheckEncryptDecryptRTPPacketsWithoutROC", func(t *testing.T) {
						ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
						assert.NoError(t, err)
						ctxEnc.SetROC(SSRC, ROC)

						ctxEncNoRCC, err := CreateContext(masterKey, masterSalt, profile, optsNoRCC...)
						assert.NoError(t, err)
						ctxEncNoRCC.SetROC(SSRC, ROC)

						ctxDec, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
						assert.NoError(t, err)
						ctxDec.SetROC(SSRC, ROC)

						rtpPacket := slices.Clone(decryptedRTPPacket)
						var header rtp.Header
						_, err = header.Unmarshal(rtpPacket)
						assert.NoError(t, err)
						header.SequenceNumber = 1
						_, err = header.MarshalTo(rtpPacket)
						assert.NoError(t, err)

						srtpPacket1, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
						assert.NoError(t, err)

						srtpPacket2, err := ctxEncNoRCC.EncryptRTP(nil, rtpPacket, nil)
						assert.NoError(t, err)

						assert.Equal(t, srtpPacket1, srtpPacket2)

						decrypted, err := ctxDec.DecryptRTP(nil, srtpPacket1, nil)
						assert.NoError(t, err)
						assert.Equal(t, rtpPacket, decrypted)
					})

					t.Run("CheckROCFromSRTPPacketIsUsed", func(t *testing.T) {
						ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
						assert.NoError(t, err)
						ctxEnc.SetROC(SSRC, ROC)

						ctxDec, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
						assert.NoError(t, err)
						// Do not set ROC in ctxDec

						rtpPacket := slices.Clone(decryptedRTPPacket)
						var header rtp.Header
						_, err = header.Unmarshal(rtpPacket)
						assert.NoError(t, err)

						for n := ROCTransmitRate - 1; n <= ROCTransmitRate+1; n++ {
							header.SequenceNumber = n
							_, err = header.MarshalTo(rtpPacket)
							assert.NoError(t, err)

							srtpPacket, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
							assert.NoError(t, err)

							_, err = ctxDec.DecryptRTP(nil, srtpPacket, nil)
							if n == ROCTransmitRate-1 {
								assert.ErrorIs(t, err, ErrFailedToVerifyAuthTag)
							} else {
								assert.NoError(t, err)
							}
						}
					})

					t.Run("CheckROCTransmitRate", func(t *testing.T) {
						ctxEnc, err := CreateContext(masterKey, masterSalt, profile, optsRCC...)
						assert.NoError(t, err)
						ctxEnc.SetROC(SSRC, ROC)

						ctxEncNoRCC, err := CreateContext(masterKey, masterSalt, profile, optsNoRCC...)
						assert.NoError(t, err)
						ctxEncNoRCC.SetROC(SSRC, ROC)

						rtpPacket := slices.Clone(decryptedRTPPacket)
						var header rtp.Header
						_, err = header.Unmarshal(rtpPacket)
						assert.NoError(t, err)

						for n := uint16(0); n <= ROCTransmitRate*4; n++ {
							header.SequenceNumber = n
							_, err = header.MarshalTo(rtpPacket)
							assert.NoError(t, err)

							srtpPacket1, err := ctxEnc.EncryptRTP(nil, rtpPacket, nil)
							assert.NoError(t, err)

							srtpPacket2, err := ctxEncNoRCC.EncryptRTP(nil, rtpPacket, nil)
							assert.NoError(t, err)

							if n%ROCTransmitRate == 0 {
								assert.NotEqual(t, srtpPacket1, srtpPacket2)
							} else {
								assert.Equal(t, srtpPacket1, srtpPacket2)
							}
						}
					})
				})
			}
		}
	}
}

func TestInvalidRCCContextOptions(t *testing.T) {
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
		keyLen, err := profile.KeyLen()
		assert.NoError(t, err)
		saltLen, err := profile.SaltLen()
		assert.NoError(t, err)
		masterKey := make([]byte, keyLen)
		masterSalt := make([]byte, saltLen)
		aeadAuthTagLen, err := profile.AEADAuthTagLen()
		assert.NoError(t, err)

		_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode1, 0))
		assert.ErrorIs(t, err, errZeroRocTransmitRate)
		_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode2, 0))
		assert.ErrorIs(t, err, errZeroRocTransmitRate)
		_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode3, 0))
		assert.ErrorIs(t, err, errZeroRocTransmitRate)

		_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode1, 10))
		assert.ErrorIs(t, err, errUnsupportedRccMmode)
		if aeadAuthTagLen == 0 {
			_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode3, 10))
		} else {
			_, err = CreateContext(masterKey, masterSalt, profile, RolloverCounterCarryingTransform(RCCMode2, 10))
		}
		assert.ErrorIs(t, err, errUnsupportedRccMmode)
	}
}
