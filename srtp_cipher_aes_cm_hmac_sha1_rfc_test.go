// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type testRfcAesCipher struct {
	profile   ProtectionProfile  // Protection profile
	keys      derivedSessionKeys // Derived session keys
	keystream []byte
}

// createRfcAesTestCiphers returns a list of test ciphers for the RFC test vectors.
func createRfcAesTestCiphers() []testRfcAesCipher {
	tests := []testRfcAesCipher{}

	// AES-128-CM, RFC 3711, Appendix B.2
	aes128Cm := testRfcAesCipher{
		profile: ProtectionProfileAes128CmHmacSha1_80,
		keys: derivedSessionKeys{
			srtpSessionKey:  fromHex(`2B7E151628AED2A6ABF7158809CF4F3C`),
			srtpSessionSalt: fromHex(`F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000`),
		},
		keystream: fromHex(`E03EAD0935C95E80E166B16DD92B4EB4
			D23513162B02D0F72A43A2FE4A5F97AB
			41E95B3BB0A2E8DD477901E4FCA894C0`),
	}
	aes128Cm.keys.srtcpSessionKey = aes128Cm.keys.srtpSessionKey
	aes128Cm.keys.srtcpSessionSalt = aes128Cm.keys.srtpSessionSalt
	tests = append(tests, aes128Cm)

	// AES-256-CM, RFC 6188, Section 7.1
	aes256Cm := testRfcAesCipher{
		profile: ProtectionProfileAes256CmHmacSha1_80,
		keys: derivedSessionKeys{
			srtpSessionKey: fromHex(`57f82fe3613fd170a85ec93c40b1f092
				2ec4cb0dc025b58272147cc438944a98`),
			srtpSessionSalt: fromHex(`f0f1f2f3f4f5f6f7f8f9fafbfcfd0000`),
		},
		keystream: fromHex(`92bdd28a93c3f52511c677d08b5515a4
			9da71b2378a854f67050756ded165bac
			63c4868b7096d88421b563b8c94c9a31`),
	}
	aes256Cm.keys.srtcpSessionKey = aes256Cm.keys.srtpSessionKey
	aes256Cm.keys.srtcpSessionSalt = aes256Cm.keys.srtpSessionSalt
	tests = append(tests, aes256Cm)

	return tests
}

func TestAesCiphersWithRfcTestVectors(t *testing.T) {
	for _, testCase := range createRfcAesTestCiphers() {
		t.Run(testCase.profile.String(), func(t *testing.T) {
			// Use zero SSRC and sequence number as specified in RFC
			rtpHeader := []byte{
				0x80, 0x0f, 0x00, 0x00, 0xde, 0xca, 0xfb, 0xad,
				0x00, 0x00, 0x00, 0x00,
			}

			t.Run("Keystream generation", func(t *testing.T) {
				cipher, err := newSrtpCipherAesCmHmacSha1WithDerivedKeys(testCase.profile, testCase.keys, true, true)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)

				// Generated AES keystream will be XOR'ed with zeroes in RTP packet payload,
				// so SRTP payload will be equal to keystream
				decryptedRTPPacket := make([]byte, len(rtpHeader)+len(testCase.keystream))
				copy(decryptedRTPPacket, rtpHeader)

				actualEncrypted, err := ctx.EncryptRTP(nil, decryptedRTPPacket, nil)
				assert.NoError(t, err)

				assert.Equal(t, rtpHeader, actualEncrypted[:len(rtpHeader)])
				assert.Equal(t, testCase.keystream, actualEncrypted[len(rtpHeader):len(rtpHeader)+len(testCase.keystream)])
			})
		})
	}
}
