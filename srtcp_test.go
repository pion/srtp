package srtp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/pion/rtcp"
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

func rtcpTestCasesSingle() map[string]rtcpTestCase {
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

func rtcpTestCases() map[string]rtcpTestCase {
	single := rtcpTestCasesSingle()
	return map[string]rtcpTestCase{
		"AEAD_AES_128_GCM": single["AEAD_AES_128_GCM"],
		"AES_128_CM_HMAC_SHA1_80": {
			algo:       ProtectionProfileAes128CmHmacSha1_80,
			masterKey:  single["AES_128_CM_HMAC_SHA1_80"].masterKey,
			masterSalt: single["AES_128_CM_HMAC_SHA1_80"].masterSalt,
			packets: []rtcpTestPacket{
				single["AES_128_CM_HMAC_SHA1_80"].packets[0],
				single["AES_128_CM_HMAC_SHA1_80"].packets[1],
				{
					ssrc:    0x11111111,
					index:   0x7ffffffe, // Upper boundary of index
					pktType: rtcp.TypeSenderReport,
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
					ssrc:    0x11111111,
					index:   0x7fffffff, // Will be wrapped to 0
					pktType: rtcp.TypeSenderReport,
					encrypted: []byte{
						0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11,
						0x17, 0x8c, 0x15, 0xf1, 0x4b, 0x11, 0xda, 0xf5,
						0x74, 0x53, 0x86, 0x2b, 0xc9, 0x07, 0x29, 0x40,
						0xbf, 0x22, 0xf6, 0x46, 0x11, 0xa4, 0xc1, 0x3a,
						0xff, 0x5a, 0xbd, 0xd0, 0xf8, 0x8b, 0x38, 0xe4,
						0x95, 0x38, 0x5d, 0xcf, 0x1b, 0xf5, 0x27, 0x77,
						0xfb, 0xdb, 0x3f, 0x10, 0x68, 0x99, 0xd8, 0xad,
						0x80, 0x00, 0x00, 0x00, 0x7d, 0x51, 0xf8, 0x0e,
						0x56, 0x40, 0x72, 0x7b, 0x9e, 0x02,
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
					if testCase.algo == ProtectionProfileAeadAes128Gcm {
						t.Skip("FIXME: DecryptRTCP(nil, input, nil) for ProtectionProfileAeadAes128Gcm changes input data")
					}
					assert := assert.New(t)
					encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo, option...)
					if err != nil {
						t.Errorf("CreateContext failed: %v", err)
					}

					decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo, option...)
					if err != nil {
						t.Errorf("CreateContext failed: %v", err)
					}

					for _, pkt := range testCase.packets {
						decryptResult, err := decryptContext.DecryptRTCP(nil, pkt.encrypted, nil)
						if err != nil {
							t.Error(err)
						}
						assert.Equal(pkt.decrypted, decryptResult, "RTCP failed to decrypt")

						encryptContext.SetIndex(pkt.ssrc, pkt.index)
						encryptResult, err := encryptContext.EncryptRTCP(nil, pkt.decrypted, nil)
						if err != nil {
							t.Error(err)
						}
						assert.Equal(pkt.encrypted, encryptResult, "RTCP failed to encrypt")
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
			if testCase.algo == ProtectionProfileAeadAes128Gcm {
				t.Skip("ProtectionProfileAeadAes128Gcm implementation currently doesn't support in-place encrypt/decrypt")
			}
			assert := assert.New(t)
			authTagLen, err := testCase.algo.authTagLen()
			assert.NoError(err)

			aeadAuthTagLen, err := testCase.algo.aeadAuthTagLen()
			assert.NoError(err)

			encryptHeader := &rtcp.Header{}
			encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			if err != nil {
				t.Errorf("CreateContext failed: %v", err)
			}

			decryptHeader := &rtcp.Header{}
			decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			if err != nil {
				t.Errorf("CreateContext failed: %v", err)
			}

			for _, pkt := range testCase.packets {
				// Copy packet, asserts that everything was done in place
				decryptInput := append([]byte{}, pkt.encrypted...)

				actualDecrypted, err := decryptContext.DecryptRTCP(decryptInput, decryptInput, decryptHeader)
				switch {
				case err != nil:
					t.Error(err)
				case decryptHeader.Type != pkt.pktType:
					t.Fatalf("DecryptRTCP failed to populate input rtcp.Header, expected: %d, got %d", pkt.pktType, decryptHeader.Type)
				case !bytes.Equal(decryptInput[:len(decryptInput)-(authTagLen+aeadAuthTagLen+srtcpIndexSize)], actualDecrypted):
					t.Fatalf("DecryptRTP failed to decrypt in place\nexpected: %v\n     got: %v", decryptInput[:len(decryptInput)-(authTagLen+srtcpIndexSize)], actualDecrypted)
				}
				assert.Equal(decryptInput[:len(decryptInput)-(authTagLen+aeadAuthTagLen+srtcpIndexSize)], actualDecrypted, "DecryptRTP failed to decrypt in place")

				assert.Equal(pkt.decrypted, actualDecrypted, "RTCP failed to decrypt")

				// Destination buffer should have capacity to store the resutl.
				// Otherwise, the buffer may be realloc-ed and the actual result will be written to the other address.
				encryptInput := make([]byte, 0, len(pkt.encrypted))
				// Copy packet, asserts that everything was done in place
				encryptInput = append(encryptInput, pkt.decrypted...)

				encryptContext.SetIndex(pkt.ssrc, pkt.index)
				actualEncrypted, err := encryptContext.EncryptRTCP(encryptInput, encryptInput, encryptHeader)
				switch {
				case err != nil:
					t.Error(err)
				case encryptHeader.Type != pkt.pktType:
					t.Fatalf("EncryptRTCP failed to populate input rtcp.Header, expected: %d, got %d", pkt.pktType, encryptHeader.Type)
				}
				assert.Equal(actualEncrypted[:len(actualEncrypted)-(authTagLen+aeadAuthTagLen+srtcpIndexSize)], encryptInput, "EncryptRTCP failed to encrypt in place")

				assert.Equal(pkt.encrypted, actualEncrypted, "RTCP failed to encrypt")
			}
		})
	}
}

// Assert that passing a dst buffer that is too short doesn't result in a failure
func TestRTCPLifecyclePartialAllocation(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			if testCase.algo == ProtectionProfileAeadAes128Gcm {
				t.Skip("FIXME: DecryptRTCP(nil, input, nil) for ProtectionProfileAeadAes128Gcm changes input data")
			}
			assert := assert.New(t)

			encryptHeader := &rtcp.Header{}
			encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			if err != nil {
				t.Errorf("CreateContext failed: %v", err)
			}

			decryptHeader := &rtcp.Header{}
			decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			if err != nil {
				t.Errorf("CreateContext failed: %v", err)
			}

			for _, pkt := range testCase.packets {
				// Copy packet, asserts that partial buffers can be used
				decryptDst := make([]byte, len(pkt.decrypted)*2)

				actualDecrypted, err := decryptContext.DecryptRTCP(decryptDst, pkt.encrypted, decryptHeader)
				if err != nil {
					t.Error(err)
				} else if decryptHeader.Type != pkt.pktType {
					t.Fatalf("DecryptRTCP failed to populate input rtcp.Header, expected: %d, got %d", pkt.pktType, decryptHeader.Type)
				}
				assert.Equal(pkt.decrypted, actualDecrypted, "RTCP failed to decrypt")

				// Copy packet, asserts that partial buffers can be used
				encryptDst := make([]byte, len(pkt.encrypted)/2)

				encryptContext.SetIndex(pkt.ssrc, pkt.index)
				actualEncrypted, err := encryptContext.EncryptRTCP(encryptDst, pkt.decrypted, encryptHeader)
				if err != nil {
					t.Error(err)
				} else if encryptHeader.Type != pkt.pktType {
					t.Fatalf("EncryptRTCP failed to populate input rtcp.Header, expected: %d, got %d", pkt.pktType, encryptHeader.Type)
				}
				assert.Equal(pkt.encrypted, actualEncrypted, "RTCP failed to encrypt")
			}
		})
	}
}

func TestRTCPInvalidAuthTag(t *testing.T) {
	for caseName, testCase := range rtcpTestCases() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assert := assert.New(t)
			authTagLen, err := testCase.algo.authTagLen()
			assert.NoError(err)

			aeadAuthTagLen, err := testCase.algo.aeadAuthTagLen()
			assert.NoError(err)

			decryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			if err != nil {
				t.Errorf("CreateContext failed: %v", err)
			}

			for _, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.encrypted...)
				decryptResult, err := decryptContext.DecryptRTCP(nil, rtcpPacket, nil)
				if err != nil {
					t.Error(err)
				}
				assert.Equal(pkt.decrypted, decryptResult, "RTCP failed to decrypt")

				// Zero out auth tag
				if authTagLen > 0 {
					copy(rtcpPacket[len(rtcpPacket)-authTagLen:], make([]byte, authTagLen))
				}
				if aeadAuthTagLen > 0 {
					authTagPos := len(rtcpPacket) - authTagLen - srtcpIndexSize - aeadAuthTagLen
					copy(rtcpPacket[authTagPos:authTagPos+aeadAuthTagLen], make([]byte, aeadAuthTagLen))
				}

				if _, err = decryptContext.DecryptRTCP(nil, rtcpPacket, nil); err == nil {
					t.Errorf("Was able to decrypt RTCP packet with invalid Auth Tag")
				}
			}
		})
	}
}

func TestRTCPReplayDetectorSeparation(t *testing.T) {
	for caseName, testCase := range rtcpTestCasesSingle() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assert := assert.New(t)
			decryptContext, err := CreateContext(
				testCase.masterKey, testCase.masterSalt, testCase.algo,
				SRTCPReplayProtection(10),
			)
			if err != nil {
				t.Errorf("CreateContext failed: %v", err)
			}

			for _, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.encrypted...)
				decryptResult, errDec := decryptContext.DecryptRTCP(nil, rtcpPacket, nil)
				if errDec != nil {
					t.Error(errDec)
				}
				assert.Equal(pkt.decrypted, decryptResult, "RTCP failed to decrypt")
			}

			for i, pkt := range testCase.packets {
				rtcpPacket := append([]byte{}, pkt.encrypted...)
				if _, err = decryptContext.DecryptRTCP(nil, rtcpPacket, nil); !errors.Is(err, errDuplicated) {
					t.Error("Was able to decrypt duplicated RTCP packet", i)
				}
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
	for caseName, testCase := range rtcpTestCasesSingle() {
		testCase := testCase
		t.Run(caseName, func(t *testing.T) {
			assert := assert.New(t)
			encryptContext, err := CreateContext(testCase.masterKey, testCase.masterSalt, testCase.algo)
			assert.NoError(err)

			authTagLen, err := testCase.algo.authTagLen()
			assert.NoError(err)

			decryptContext, err := CreateContext(
				testCase.masterKey, testCase.masterSalt, testCase.algo,
				SRTCPReplayProtection(10),
			)
			assert.NoError(err)

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
				assert.NoError(err)
				encryptedRCTPs[i] = encrypted
			}

			for i, expectedIndex := range expectedIndexes {
				assert.Equal(expectedIndex, getRTCPIndex(encryptedRCTPs[i], authTagLen), "RTCP index does not match")
			}

			for i, output := range encryptedRCTPs {
				decrypted, err := decryptContext.DecryptRTCP(nil, output, encryptHeader)
				assert.NoError(err)
				assert.Equal(decrypted, inputs[i])
			}
		})
	}
}
