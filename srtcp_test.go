// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"
	"testing"

	"github.com/pion/rtcp"
	"github.com/pion/transport/v3/replaydetector"
	"github.com/stretchr/testify/assert"
)

type rtcpTestPacket struct {
	ssrc      uint32
	index     uint32
	pktType   rtcp.PacketType
	encrypted []byte
	decrypted []byte
}

type rtcpTestCase struct {
	algo       ProtectionProfile
	masterKey  []byte
	masterSalt []byte
	packets    []rtcpTestPacket
}

func rtcpTestCases() map[string]rtcpTestCase {
	return map[string]rtcpTestCase{
		"AEAD_AES_128_GCM": {
			algo:       ProtectionProfileAeadAes128Gcm,
			masterKey:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			masterSalt: []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab},
			packets: []rtcpTestPacket{
				{
					ssrc:    0xcafebabe,
					index:   0,
					pktType: rtcp.TypeSenderReport,
					encrypted: []byte{
						0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
						0xc9, 0x8b, 0x8b, 0x5d, 0xf0, 0x39, 0x2a, 0x55,
						0x85, 0x2b, 0x6c, 0x21, 0xac, 0x8e, 0x70, 0x25,
						0xc5, 0x2c, 0x6f, 0xbe, 0xa2, 0xb3, 0xb4, 0x46,
						0xea, 0x31, 0x12, 0x3b, 0xa8, 0x8c, 0xe6, 0x1e,
						0x80, 0x00, 0x00, 0x01,
					},
					decrypted: []byte{
						0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
						0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
						0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
					},
				},
			},
		},
		"AES_128_CM_HMAC_SHA1_80": {
			algo:       ProtectionProfileAes128CmHmacSha1_80,
			masterKey:  []byte{0xfd, 0xa6, 0x25, 0x95, 0xd7, 0xf6, 0x92, 0x6f, 0x7d, 0x9c, 0x02, 0x4c, 0xc9, 0x20, 0x9f, 0x34},
			masterSalt: []byte{0xa9, 0x65, 0x19, 0x85, 0x54, 0x0b, 0x47, 0xbe, 0x2f, 0x27, 0xa8, 0xb8, 0x81, 0x23},
			packets: []rtcpTestPacket{
				{
					ssrc:    0x66ef91ff,
					index:   0,
					pktType: rtcp.TypeSenderReport,
					encrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff,
						0xcd, 0x34, 0xc5, 0x78, 0xb2, 0x8b, 0xe1, 0x6b,
						0xc5, 0x09, 0xd5, 0x77, 0xe4, 0xce, 0x5f, 0x20,
						0x80, 0x21, 0xbd, 0x66, 0x74, 0x65, 0xe9, 0x5f,
						0x49, 0xe5, 0xf5, 0xc0, 0x68, 0x4e, 0xe5, 0x6a,
						0x78, 0x07, 0x75, 0x46, 0xed, 0x90, 0xf6, 0xdc,
						0x9d, 0xef, 0x3b, 0xdf, 0xf2, 0x79, 0xa9, 0xd8,
						0x80, 0x00, 0x00, 0x01, 0x60, 0xc0, 0xae, 0xb5,
						0x6f, 0x40, 0x88, 0x0e, 0x28, 0xba,
					},
					decrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff,
						0xdf, 0x48, 0x80, 0xdd, 0x61, 0xa6, 0x2e, 0xd3,
						0xd8, 0xbc, 0xde, 0xbe, 0x00, 0x00, 0x00, 0x09,
						0x00, 0x00, 0x16, 0x04, 0x81, 0xca, 0x00, 0x06,
						0x66, 0xef, 0x91, 0xff, 0x01, 0x10, 0x52, 0x6e,
						0x54, 0x35, 0x43, 0x6d, 0x4a, 0x68, 0x7a, 0x79,
						0x65, 0x74, 0x41, 0x78, 0x77, 0x2b, 0x00, 0x00,
					},
				},
				{
					ssrc:    0x11111111,
					index:   0,
					pktType: rtcp.TypeSenderReport,
					encrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x17, 0x8c, 0x15, 0xf1, 0x4b, 0x11, 0xda, 0xf5,
						0x74, 0x53, 0x86, 0x2b, 0xc9, 0x07, 0x29, 0x40,
						0xbf, 0x22, 0xf6, 0x46, 0x11, 0xa4, 0xc1, 0x3a,
						0xff, 0x5a, 0xbd, 0xd0, 0xf8, 0x8b, 0x38, 0xe4,
						0x95, 0x38, 0x5d, 0xcf, 0x1b, 0xf5, 0x27, 0x77,
						0xfb, 0xdb, 0x3f, 0x10, 0x68, 0x99, 0xd8, 0xad,
						0x80, 0x00, 0x00, 0x01, 0x34, 0x3c, 0x2e, 0x83,
						0x17, 0x13, 0x93, 0x69, 0xcf, 0xc0,
					},
					decrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0xdf, 0x48, 0x80, 0xdd, 0x61, 0xa6, 0x2e, 0xd3,
						0xd8, 0xbc, 0xde, 0xbe, 0x00, 0x00, 0x00, 0x09,
						0x00, 0x00, 0x16, 0x04, 0x81, 0xca, 0x00, 0x06,
						0x66, 0xef, 0x91, 0xff, 0x01, 0x10, 0x52, 0x6e,
						0x54, 0x35, 0x43, 0x6d, 0x4a, 0x68, 0x7a, 0x79,
						0x65, 0x74, 0x41, 0x78, 0x77, 0x2b, 0x00, 0x00,
					},
				},
			},
		},
	}
}

func TestRTCPLifecycle(t *testing.T) {
	options := map[string][]ContextOption{
		"Default":              {},
		"WithReplayProtection": {SRTCPReplayProtection(10)},
	}

	for name, option := range options {
		option := option
		t.Run(name, func(t *testing.T) {
			for caseName, testCase := range rtcpTestCases() {
				testCase := testCase
				t.Run(caseName, func(t *testing.T) {
					assertT := assert.New(t)
					encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo, option...)
					assertT.NoError(err)

					decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo, option...)
					assertT.NoError(err)

					for _, pkt := range testCase.packets {
						decryptResult, err := decryptContext.DecryptRTCP(nil, pkt.encrypted, nil)
						assertT.NoError(err)
						assertT.Equal(pkt.decrypted, decryptResult, "RTCP failed to decrypt")

						encryptContext.SetIndex(pkt.ssrc, pkt.index)
						encryptResult, err := encryptContext.EncryptRTCP(nil, pkt.decrypted, nil)
						assertT.NoError(err)
						assertT.Equal(pkt.encrypted, encryptResult, "RTCP failed to encrypt")
					}
				})
			}
		})
	}
}

func TestRTCPLifecycleInPlace(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assertT := assert.New(t)
			authTagLen, err := testCase.algo.AuthTagRTCPLen()
			assertT.NoError(err)

			aeadAuthTagLen, err := testCase.algo.AEADAuthTagLen()
			assertT.NoError(err)

			encryptHeader := &rtcp.Header{}
			encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assertT.NoError(err)

			decryptHeader := &rtcp.Header{}
			decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assertT.NoError(err)

			for _, pkt := range testCase.packets {
				// Copy packet, asserts that everything was done in place
				decryptInput := append([]byte{}, pkt.encrypted...)

				actualDecrypted, err := decryptContext.DecryptRTCP(decryptInput, decryptInput, decryptHeader)
				assertT.NoError(err)
				assertT.Equal(pkt.pktType, decryptHeader.Type, "DecryptRTCP failed to populate input rtcp.Header")
				assertT.Equal(decryptInput[:len(decryptInput)-(authTagLen+aeadAuthTagLen+srtcpIndexSize)], actualDecrypted,
					"DecryptRTCP failed to decrypt in place")

				assertT.Equal(pkt.decrypted, actualDecrypted, "RTCP failed to decrypt")

				// Destination buffer should have capacity to store the resutl.
				// Otherwise, the buffer may be realloc-ed and the actual result will be written to the other address.
				encryptInput := make([]byte, 0, len(pkt.encrypted))
				// Copy packet, asserts that everything was done in place
				encryptInput = append(encryptInput, pkt.decrypted...)

				encryptContext.SetIndex(pkt.ssrc, pkt.index)
				actualEncrypted, err := encryptContext.EncryptRTCP(encryptInput, encryptInput, encryptHeader)
				assertT.NoError(err)
				assertT.Equal(pkt.pktType, encryptHeader.Type, "EncryptRTCP failed to populate input rtcp.Header")
				assertT.Equal(actualEncrypted[:len(actualEncrypted)-(authTagLen+aeadAuthTagLen+srtcpIndexSize)],
					encryptInput, "EncryptRTCP failed to encrypt in place")

				assertT.Equal(pkt.encrypted, actualEncrypted, "RTCP failed to encrypt")
			}
		})
	}
}

// Assert that passing a dst buffer that is too short doesn't result in a failure.
func TestRTCPLifecyclePartialAllocation(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assertT := assert.New(t)
			encryptHeader := &rtcp.Header{}
			encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assertT.NoError(err)

			decryptHeader := &rtcp.Header{}
			decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assertT.NoError(err)

			for _, pkt := range testCase.packets {
				// Copy packet, asserts that partial buffers can be used
				decryptDst := make([]byte, len(pkt.decrypted)*2)

				actualDecrypted, err := decryptContext.DecryptRTCP(decryptDst, pkt.encrypted, decryptHeader)
				assertT.NoError(err)
				assertT.Equal(pkt.pktType, decryptHeader.Type, "DecryptRTCP failed to populate input rtcp.Header")
				assertT.Equal(pkt.decrypted, actualDecrypted, "RTCP failed to decrypt")

				// Copy packet, asserts that partial buffers can be used
				encryptDst := make([]byte, len(pkt.encrypted)/2)

				encryptContext.SetIndex(pkt.ssrc, pkt.index)
				actualEncrypted, err := encryptContext.EncryptRTCP(encryptDst, pkt.decrypted, encryptHeader)
				assertT.NoError(err)
				assertT.Equal(pkt.pktType, encryptHeader.Type, "EncryptRTCP failed to populate input rtcp.Header")
				assertT.Equal(pkt.encrypted, actualEncrypted, "RTCP failed to encrypt")
			}
		})
	}
}

func TestRTCPInvalidAuthTag(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assertT := assert.New(t)
			authTagLen, err := testCase.algo.AuthTagRTCPLen()
			assertT.NoError(err)

			aeadAuthTagLen, err := testCase.algo.AEADAuthTagLen()
			assertT.NoError(err)

			decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assertT.NoError(err)

			for _, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.encrypted...)
				decryptResult, err := decryptContext.DecryptRTCP(nil, rtcpPacket, nil)
				assertT.NoError(err)
				assertT.Equal(pkt.decrypted, decryptResult, "RTCP failed to decrypt")

				// Zero out auth tag
				if authTagLen > 0 {
					copy(rtcpPacket[len(rtcpPacket)-authTagLen:], make([]byte, authTagLen))
				}
				if aeadAuthTagLen > 0 {
					authTagPos := len(rtcpPacket) - authTagLen - srtcpIndexSize - aeadAuthTagLen
					copy(rtcpPacket[authTagPos:authTagPos+aeadAuthTagLen], make([]byte, aeadAuthTagLen))
				}
				_, err = decryptContext.DecryptRTCP(nil, rtcpPacket, nil)
				assertT.Error(err, "Was able to decrypt RTCP packet with invalid Auth Tag")
			}
		})
	}
}

func TestRTCPReplayDetectorSeparation(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assertT := assert.New(t)
			decryptContext, err := CreateContext(
				testCase.masterKey, testCase.masterSalt, testCase.algo,
				SRTCPReplayProtection(10),
			)
			assertT.NoError(err)

			for _, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.encrypted...)
				decryptResult, errDec := decryptContext.DecryptRTCP(nil, rtcpPacket, nil)
				assertT.NoError(errDec)
				assertT.Equal(pkt.decrypted, decryptResult, "RTCP failed to decrypt")
			}

			for i, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.encrypted...)
				_, err = decryptContext.DecryptRTCP(nil, rtcpPacket, nil)
				assertT.ErrorIs(err, errDuplicated, "RTCP packet %d was not detected as replayed", i)
			}
		})
	}
}

func getRTCPIndex(encrypted []byte, authTagLen int) uint32 {
	tailOffset := len(encrypted) - (authTagLen + srtcpIndexSize)
	srtcpIndexBuffer := encrypted[tailOffset : tailOffset+srtcpIndexSize]

	return binary.BigEndian.Uint32(srtcpIndexBuffer) &^ (1 << 31)
}

func TestEncryptRTCPSeparation(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assertT := assert.New(t)
			encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assertT.NoError(err)

			authTagLen, err := testCase.algo.AuthTagRTCPLen()
			assertT.NoError(err)

			decryptContext, err := CreateContext(
				testCase.masterKey, testCase.masterSalt, testCase.algo,
				SRTCPReplayProtection(10),
			)
			assertT.NoError(err)

			encryptHeader := &rtcp.Header{}

			inputs := [][]byte{}
			expectedIndexes := []uint32{}
			pktCnt := map[uint32]uint32{}
			for _, pkt := range testCase.packets {
				inputs = append(inputs, pkt.decrypted)
				pktCnt[pkt.ssrc]++
				expectedIndexes = append(expectedIndexes, pktCnt[pkt.ssrc])
			}
			for _, pkt := range testCase.packets {
				inputs = append(inputs, pkt.decrypted)
				pktCnt[pkt.ssrc]++
				expectedIndexes = append(expectedIndexes, pktCnt[pkt.ssrc])
			}
			encryptedRCTPs := make([][]byte, len(inputs))

			for i, input := range inputs {
				encrypted, err := encryptContext.EncryptRTCP(nil, input, encryptHeader)
				assertT.NoError(err)
				encryptedRCTPs[i] = encrypted
			}

			for i, expectedIndex := range expectedIndexes {
				assertT.Equal(expectedIndex, getRTCPIndex(encryptedRCTPs[i], authTagLen), "RTCP index does not match")
			}

			for i, output := range encryptedRCTPs {
				decrypted, err := decryptContext.DecryptRTCP(nil, output, encryptHeader)
				assertT.NoError(err)
				assertT.Equal(decrypted, inputs[i])
			}
		})
	}
}

func TestRTCPDecryptShortenedPacket(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			pkt := testCase.packets[0]
			for i := 1; i < len(pkt.encrypted)-1; i++ {
				packet := pkt.encrypted[:i]
				decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
				assert.NoError(t, err)
				assert.NotPanics(t, func() {
					_, _ = decryptContext.DecryptRTCP(nil, packet, nil)
				}, "Panic on length %d/%d", i, len(pkt.encrypted))
			}
		})
	}
}

func TestRTCPMaxPackets(t *testing.T) {
	const ssrc = 0x11111111
	testCases := map[string]rtcpTestCase{
		"AEAD_AES_128_GCM": {
			algo:       ProtectionProfileAeadAes128Gcm,
			masterKey:  []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			masterSalt: []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab},
			packets: []rtcpTestPacket{
				{
					pktType: rtcp.TypeSenderReport,
					encrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x02, 0xb6, 0xc1, 0x47, 0x92, 0xbe, 0xf0, 0xae,
						0xd9, 0x40, 0xa5, 0x1c, 0xbe, 0xec, 0xaf, 0xfc,
						0x7d, 0x86, 0x3b, 0xbb, 0x93, 0x0c, 0xb0, 0xd4,
						0xea, 0x4a, 0x3c, 0x5b, 0xd1, 0xd5, 0x47, 0xb1,
						0x1a, 0x61, 0xae, 0xa6, 0x1a, 0x0c, 0xb9, 0x14,
						0xa5, 0x16, 0x08, 0xe4, 0xfb, 0x0d, 0x15, 0xba,
						0x7f, 0x70, 0x2b, 0xb8, 0x99, 0x97, 0x91, 0xfd,
						0x53, 0x03, 0xcd, 0x57, 0xbb, 0x8f, 0x93, 0xbe,
						0xff, 0xff, 0xff, 0xff,
					},
					decrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x04, 0x99, 0x47, 0x53, 0xc4, 0x1e, 0xb9, 0xde,
						0x52, 0xa3, 0x1d, 0x77, 0x2f, 0xff, 0xcc, 0x75,
						0xbb, 0x6a, 0x29, 0xb8, 0x01, 0xb7, 0x2e, 0x4b,
						0x4e, 0xcb, 0xa4, 0x81, 0x2d, 0x46, 0x04, 0x5e,
						0x86, 0x90, 0x17, 0x4f, 0x4d, 0x78, 0x2f, 0x58,
						0xb8, 0x67, 0x91, 0x89, 0xe3, 0x61, 0x01, 0x7d,
					},
				},
				{
					pktType: rtcp.TypeSenderReport,
					encrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x77, 0x47, 0x0c, 0x21, 0xc2, 0xcd, 0x33, 0xa7,
						0x5a, 0x81, 0xb5, 0xb5, 0x8f, 0xe2, 0x34, 0x28,
						0x11, 0xa8, 0xa3, 0x34, 0xf8, 0x9d, 0xfc, 0xd8,
						0xcb, 0x87, 0xe2, 0x51, 0x8e, 0xae, 0xdb, 0xfd,
						0x9d, 0xf1, 0xfa, 0x18, 0xe2, 0xdc, 0x0a, 0xd4,
						0xe3, 0x06, 0x18, 0xff, 0xf7, 0x27, 0x92, 0x1f,
						0x28, 0xcd, 0x3c, 0xf8, 0xa4, 0x0a, 0x2b, 0xbb,
						0x5b, 0x1f, 0x4d, 0x1f, 0xef, 0x0e, 0xc4, 0x91,
						0x80, 0x00, 0x00, 0x01,
					},
					decrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0xda, 0xb5, 0xe0, 0x56, 0x9a, 0x4a, 0x74, 0xed,
						0x8a, 0x54, 0x0c, 0xcf, 0xd5, 0x09, 0xb1, 0x40,
						0x01, 0x42, 0xc3, 0x9a, 0x76, 0x00, 0xa9, 0xd4,
						0xf7, 0x29, 0x9e, 0x51, 0xfb, 0x3c, 0xc1, 0x74,
						0x72, 0xf9, 0x52, 0xb1, 0x92, 0x31, 0xca, 0x22,
						0xab, 0x3e, 0xc5, 0x5f, 0x83, 0x34, 0xf0, 0x28,
					},
				},
			},
		},
		"AES_128_CM_HMAC_SHA1_80": {
			algo:       ProtectionProfileAes128CmHmacSha1_80,
			masterKey:  []byte{0xfd, 0xa6, 0x25, 0x95, 0xd7, 0xf6, 0x92, 0x6f, 0x7d, 0x9c, 0x02, 0x4c, 0xc9, 0x20, 0x9f, 0x34},
			masterSalt: []byte{0xa9, 0x65, 0x19, 0x85, 0x54, 0x0b, 0x47, 0xbe, 0x2f, 0x27, 0xa8, 0xb8, 0x81, 0x23},
			packets: []rtcpTestPacket{
				{
					encrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x17, 0x8c, 0x15, 0xf1, 0x4b, 0x11, 0xda, 0xf5,
						0x74, 0x53, 0x86, 0x2b, 0xc9, 0x07, 0x29, 0x40,
						0xbf, 0x22, 0xf6, 0x46, 0x11, 0xa4, 0xc1, 0x3a,
						0xff, 0x5a, 0xbd, 0xd0, 0xf8, 0x8b, 0x38, 0xe4,
						0x95, 0x38, 0x5d, 0xcf, 0x1b, 0xf5, 0x27, 0x77,
						0xfb, 0xdb, 0x3f, 0x10, 0x68, 0x99, 0xd8, 0xad,
						0xff, 0xff, 0xff, 0xff, 0x5a, 0x99, 0xce, 0xed,
						0x9f, 0x2e, 0x4d, 0x9d, 0xfa, 0x97,
					},
					decrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x04, 0x99, 0x47, 0x53, 0xc4, 0x1e, 0xb9, 0xde,
						0x52, 0xa3, 0x1d, 0x77, 0x2f, 0xff, 0xcc, 0x75,
						0xbb, 0x6a, 0x29, 0xb8, 0x01, 0xb7, 0x2e, 0x4b,
						0x4e, 0xcb, 0xa4, 0x81, 0x2d, 0x46, 0x04, 0x5e,
						0x86, 0x90, 0x17, 0x4f, 0x4d, 0x78, 0x2f, 0x58,
						0xb8, 0x67, 0x91, 0x89, 0xe3, 0x61, 0x01, 0x7d,
					},
				},
				{
					encrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x12, 0x71, 0x75, 0x7a, 0xb0, 0xfd, 0x80, 0xcb,
						0x26, 0xbb, 0x54, 0x5a, 0x1c, 0x0e, 0x98, 0x09,
						0xbe, 0x60, 0x23, 0xd8, 0xe6, 0x6e, 0x68, 0xe8,
						0x6e, 0x9c, 0xb2, 0x7e, 0x02, 0xa7, 0xab, 0xfe,
						0xb3, 0xf4, 0x4c, 0x13, 0xc3, 0xac, 0x97, 0x2c,
						0x35, 0x91, 0xbb, 0x37, 0x9c, 0x86, 0x28, 0x85,
						0x80, 0x00, 0x00, 0x01, 0x89, 0x76, 0x07, 0xca,
						0xd9, 0xc4, 0xcb, 0xca, 0x66, 0xab,
					},
					decrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0xda, 0xb5, 0xe0, 0x56, 0x9a, 0x4a, 0x74, 0xed,
						0x8a, 0x54, 0x0c, 0xcf, 0xd5, 0x09, 0xb1, 0x40,
						0x01, 0x42, 0xc3, 0x9a, 0x76, 0x00, 0xa9, 0xd4,
						0xf7, 0x29, 0x9e, 0x51, 0xfb, 0x3c, 0xc1, 0x74,
						0x72, 0xf9, 0x52, 0xb1, 0x92, 0x31, 0xca, 0x22,
						0xab, 0x3e, 0xc5, 0x5f, 0x83, 0x34, 0xf0, 0x28,
					},
				},
			},
		},
	}

	for caseName, testCase := range testCases {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assertT := assert.New(t)
			encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assertT.NoError(err)

			decryptContext, err := CreateContext(
				testCase.masterKey,
				testCase.masterSalt,
				testCase.algo,
				SRTCPReplayProtection(10),
			)
			assertT.NoError(err)

			// Upper boundary of index
			encryptContext.SetIndex(ssrc, 0x7ffffffe)

			decryptResult, err := decryptContext.DecryptRTCP(nil, testCase.packets[0].encrypted, nil)
			assertT.NoError(err)
			assertT.Equal(testCase.packets[0].decrypted, decryptResult, "RTCP failed to decrypt")

			encryptResult, err := encryptContext.EncryptRTCP(nil, testCase.packets[0].decrypted, nil)
			assertT.NoError(err)
			assertT.Equal(testCase.packets[0].encrypted, encryptResult, "RTCP failed to encrypt")

			// Next packet will exceeds the maximum packet count
			_, err = decryptContext.DecryptRTCP(nil, testCase.packets[1].encrypted, nil)
			assertT.ErrorIs(err, errDuplicated)

			_, err = encryptContext.EncryptRTCP(nil, testCase.packets[1].decrypted, nil)
			assertT.ErrorIs(err, errExceededMaxPackets)
		})
	}
}

func TestRTCPReplayDetectorFactory(t *testing.T) {
	assertT := assert.New(t)
	testCase := rtcpTestCases()["AEAD_AES_128_GCM"]
	data := testCase.packets[0]

	var cntFactory int
	decryptContext, err := CreateContext(
		testCase.masterKey, testCase.masterSalt, testCase.algo,
		SRTCPReplayDetectorFactory(func() replaydetector.ReplayDetector {
			cntFactory++

			return &nopReplayDetector{}
		}),
	)
	assertT.NoError(err)

	_, err = decryptContext.DecryptRTCP(nil, data.encrypted, nil)
	assertT.NoError(err)
	assertT.Equal(1, cntFactory)
}

func TestDecryptInvalidSRTCP(t *testing.T) {
	assertT := assert.New(t)
	key := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	salt := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	decryptContext, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80)
	assertT.NoError(err)

	packet := []byte{0x8f, 0x48, 0xff, 0xff, 0xec, 0x77, 0xb0, 0x43, 0xf9, 0x04, 0x51, 0xff, 0xfb, 0xdf}
	_, err = decryptContext.DecryptRTCP(nil, packet, nil)
	assertT.Error(err)
}

func TestEncryptInvalidRTCP(t *testing.T) {
	assertT := assert.New(t)
	key := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	salt := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	decryptContext, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80)
	assertT.NoError(err)

	packet := []byte{0xbb, 0xbb, 0x0a, 0x2f}
	_, err = decryptContext.EncryptRTCP(nil, packet, nil)
	assertT.Error(err)
}

func TestRTCPInvalidMKI(t *testing.T) {
	mki1 := []byte{0x01, 0x02, 0x03, 0x04}
	mki2 := []byte{0x02, 0x03, 0x04, 0x05}

	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			encryptContext, err := CreateContext(
				testCase.masterKey,
				testCase.masterSalt,
				testCase.algo,
				MasterKeyIndicator(mki1),
			)
			assert.NoError(t, err)

			decryptContext, err := CreateContext(
				testCase.masterKey,
				testCase.masterSalt,
				testCase.algo,
				MasterKeyIndicator(mki2),
			)
			assert.NoError(t, err)

			for _, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.decrypted...)
				encrypted, err := encryptContext.encryptRTCP(nil, rtcpPacket)
				assert.NoError(t, err)

				_, err = decryptContext.DecryptRTCP(nil, encrypted, nil)
				assert.ErrorIs(t, err, ErrMKINotFound, "Managed to decrypt with incorrect MKI for packet with SSRC: %d", pkt.ssrc)
			}
		})
	}
}

func TestRTCPHandleMultipleMKI(t *testing.T) { //nolint:cyclop
	mki1 := []byte{0x01, 0x02, 0x03, 0x04}
	mki2 := []byte{0x02, 0x03, 0x04, 0x05}

	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			masterKey2 := make([]byte, len(testCase.masterKey))
			copy(masterKey2, testCase.masterKey)
			masterKey2[0] = ^masterKey2[0]

			encryptContext1, err := CreateContext(
				testCase.masterKey,
				testCase.masterSalt,
				testCase.algo,
				MasterKeyIndicator(mki1),
			)
			assert.NoError(t, err)

			encryptContext2, err := CreateContext(masterKey2, testCase.masterSalt, testCase.algo, MasterKeyIndicator(mki2))
			assert.NoError(t, err)

			decryptContext, err := CreateContext(
				testCase.masterKey,
				testCase.masterSalt,
				testCase.algo,
				MasterKeyIndicator(mki1),
			)
			assert.NoError(t, err)

			err = decryptContext.AddCipherForMKI(mki2, masterKey2, testCase.masterSalt)
			assert.NoError(t, err)

			for _, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.decrypted...)
				encrypted1, err := encryptContext1.encryptRTCP(nil, rtcpPacket)
				assert.NoError(t, err)

				encrypted2, err := encryptContext2.encryptRTCP(nil, rtcpPacket)
				assert.NoError(t, err)

				decrypted1, err := decryptContext.DecryptRTCP(nil, encrypted1, nil)
				assert.NoError(t, err)

				decrypted2, err := decryptContext.DecryptRTCP(nil, encrypted2, nil)
				assert.NoError(t, err)

				assert.Equal(t, rtcpPacket, decrypted1)
				assert.Equal(t, rtcpPacket, decrypted2)
			}
		})
	}
}

func TestRTCPSwitchMKI(t *testing.T) { //nolint:cyclop
	mki1 := []byte{0x01, 0x02, 0x03, 0x04}
	mki2 := []byte{0x02, 0x03, 0x04, 0x05}

	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			masterKey2 := make([]byte, len(testCase.masterKey))
			copy(masterKey2, testCase.masterKey)
			masterKey2[0] = ^masterKey2[0]

			encryptContext, err := CreateContext(
				testCase.masterKey,
				testCase.masterSalt,
				testCase.algo,
				MasterKeyIndicator(mki1),
			)
			assert.NoError(t, err)

			err = encryptContext.AddCipherForMKI(mki2, masterKey2, testCase.masterSalt)
			assert.NoError(t, err)

			decryptContext1, err := CreateContext(
				testCase.masterKey,
				testCase.masterSalt,
				testCase.algo,
				MasterKeyIndicator(mki1),
			)
			assert.NoError(t, err)

			decryptContext2, err := CreateContext(masterKey2, testCase.masterSalt, testCase.algo, MasterKeyIndicator(mki2))
			assert.NoError(t, err)

			for _, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.decrypted...)
				encrypted1, err := encryptContext.encryptRTCP(nil, rtcpPacket)
				assert.NoError(t, err)

				err = encryptContext.SetSendMKI(mki2)
				assert.NoError(t, err)

				encrypted2, err := encryptContext.encryptRTCP(nil, rtcpPacket)
				assert.NoError(t, err)

				assert.NotEqual(t, encrypted1, encrypted2)

				decrypted1, err := decryptContext1.DecryptRTCP(nil, encrypted1, nil)
				assert.NoError(t, err)
				decrypted2, err := decryptContext2.DecryptRTCP(nil, encrypted2, nil)
				assert.NoError(t, err)

				assert.Equal(t, rtcpPacket, decrypted1)
				assert.Equal(t, rtcpPacket, decrypted2)

				err = encryptContext.SetSendMKI(mki1)
				assert.NoError(t, err)
			}
		})
	}
}
