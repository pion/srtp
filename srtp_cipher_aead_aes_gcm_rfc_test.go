// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func fromHex(t *testing.T, s string) []byte {
	t.Helper()

	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\r", "")
	b, err := hex.DecodeString(s)
	assert.NoError(t, err)

	return b
}

type testRfcAeadCipher struct {
	profile ProtectionProfile  // Protection profile
	keys    derivedSessionKeys // Derived session keys

	decryptedRTPPacket     []byte
	encryptedRTPPacket     []byte
	authenticatedRTPPacket []byte

	decryptedRTCPPacket     []byte
	encryptedRTCPPacket     []byte
	authenticatedRTCPPacket []byte
}

// createRfcAeadTestCiphers returns a list of test ciphers for the RFC test vectors.
func createRfcAeadTestCiphers(t *testing.T) []testRfcAeadCipher {
	t.Helper()
	tests := []testRfcAeadCipher{}

	// AES-128-GCM, RFC 7714, Sections 16 and 17
	aes128Gcm := testRfcAeadCipher{
		profile: ProtectionProfileAeadAes128Gcm,
		keys: derivedSessionKeys{
			srtpSessionKey:  fromHex(t, `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f`),
			srtpSessionSalt: fromHex(t, `51 75 69 64 20 70 72 6f 20 71 75 6f`),
		},
		decryptedRTPPacket: fromHex(t, `8040f17b 8041f8d3 5501a0b2 47616c6c
			69612065 7374206f 6d6e6973 20646976
			69736120 696e2070 61727465 73207472
			6573`),
		encryptedRTPPacket: fromHex(t, `8040f17b 8041f8d3 5501a0b2 f24de3a3
			fb34de6c acba861c 9d7e4bca be633bd5
			0d294e6f 42a5f47a 51c7d19b 36de3adf
			8833899d 7f27beb1 6a9152cf 765ee439
			0cce`),
		authenticatedRTPPacket: fromHex(t, `8040f17b 8041f8d3 5501a0b2 47616c6c
			69612065 7374206f 6d6e6973 20646976
			69736120 696e2070 61727465 73207472
			65732249 3f82d2bc e397e9d7 9e3b19aa
			4216`),
		decryptedRTCPPacket: fromHex(t, `81c8000d 4d617273 4e545031 4e545032
			52545020 0000042a 0000e930 4c756e61
			deadbeef deadbeef deadbeef deadbeef
			deadbeef`),
		encryptedRTCPPacket: fromHex(t, `81c8000d 4d617273 63e94885 dcdab67c
			a727d766 2f6b7e99 7ff5c0f7 6c06f32d
			c676a5f1 730d6fda 4ce09b46 86303ded
			0bb9275b c84aa458 96cf4d2f c5abf872
			45d9eade 800005d4`),
		authenticatedRTCPPacket: fromHex(t, `81c8000d 4d617273 4e545031 4e545032
			52545020 0000042a 0000e930 4c756e61
			deadbeef deadbeef deadbeef deadbeef
			deadbeef 841dd968 3dd78ec9 2ae58790
			125f62b3 000005d4`),
	}
	aes128Gcm.keys.srtcpSessionKey = aes128Gcm.keys.srtpSessionKey
	aes128Gcm.keys.srtcpSessionSalt = aes128Gcm.keys.srtpSessionSalt
	tests = append(tests, aes128Gcm)

	// AES-256-GCM, RFC 7714, Sections 16 and 17
	aes256Gcm := testRfcAeadCipher{
		profile: ProtectionProfileAeadAes256Gcm,
		keys: derivedSessionKeys{
			srtpSessionKey: fromHex(t, `00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
				10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f`),
			srtpSessionSalt: fromHex(t, `51 75 69 64 20 70 72 6f 20 71 75 6f`),
		},
		decryptedRTPPacket: fromHex(t, `8040f17b 8041f8d3 5501a0b2 47616c6c
			69612065 7374206f 6d6e6973 20646976
			69736120 696e2070 61727465 73207472
			6573`),
		encryptedRTPPacket: fromHex(t, `8040f17b 8041f8d3 5501a0b2 32b1de78
			a822fe12 ef9f78fa 332e33aa b1801238
			9a58e2f3 b50b2a02 76ffae0f 1ba63799
			b87b7aa3 db36dfff d6b0f9bb 7878d7a7
			6c13`),
		authenticatedRTPPacket: fromHex(t, `8040f17b 8041f8d3 5501a0b2 47616c6c
			69612065 7374206f 6d6e6973 20646976
			69736120 696e2070 61727465 73207472
			6573a866 d5910f88 7463067c eefec452
			15d4`),
		decryptedRTCPPacket: fromHex(t, `81c8000d 4d617273 4e545031 4e545032
			52545020 0000042a 0000e930 4c756e61
			deadbeef deadbeef deadbeef deadbeef
			deadbeef`),
		encryptedRTCPPacket: fromHex(t, `81c8000d 4d617273 d50ae4d1 f5ce5d30
			4ba297e4 7d470c28 2c3ece5d bffe0a50
			a2eaa5c1 110555be 8415f658 c61de047
			6f1b6fad 1d1eb30c 4446839f 57ff6f6c
			b26ac3be 800005d4`),
		authenticatedRTCPPacket: fromHex(t, `81c8000d 4d617273 4e545031 4e545032
			52545020 0000042a 0000e930 4c756e61
			deadbeef deadbeef deadbeef deadbeef
			deadbeef 91db4afb feee5a97 8fab4393
			ed2615fe 000005d4`),
	}
	aes256Gcm.keys.srtcpSessionKey = aes256Gcm.keys.srtpSessionKey
	aes256Gcm.keys.srtcpSessionSalt = aes256Gcm.keys.srtpSessionSalt
	tests = append(tests, aes256Gcm)

	return tests
}

func TestAeadCiphersWithRfcTestVectors(t *testing.T) {
	for _, testCase := range createRfcAeadTestCiphers(t) {
		t.Run(testCase.profile.String(), func(t *testing.T) {
			t.Run("Encrypt RTP", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, true, true)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualEncrypted, err := ctx.EncryptRTP(nil, testCase.decryptedRTPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.encryptedRTPPacket, actualEncrypted)
			})

			t.Run("Decrypt RTP", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, true, true)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualDecrypted, err := ctx.DecryptRTP(nil, testCase.encryptedRTPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.decryptedRTPPacket, actualDecrypted)
			})

			t.Run("Encrypt RTCP", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, true, true)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualEncrypted, err := ctx.EncryptRTCP(nil, testCase.decryptedRTCPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.encryptedRTCPPacket, actualEncrypted)
			})

			t.Run("Decrypt RTCP", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, true, true)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualDecrypted, err := ctx.DecryptRTCP(nil, testCase.encryptedRTCPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.decryptedRTCPPacket, actualDecrypted)
			})

			t.Run("Encrypt RTP with NULL cipher", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, false, false)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualEncrypted, err := ctx.EncryptRTP(nil, testCase.decryptedRTPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.authenticatedRTPPacket, actualEncrypted)
			})

			t.Run("Decrypt RTP with NULL cipher", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, false, false)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualDecrypted, err := ctx.DecryptRTP(nil, testCase.authenticatedRTPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.decryptedRTPPacket, actualDecrypted)
			})

			t.Run("Encrypt RTCP with NULL cipher", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, false, false)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualEncrypted, err := ctx.EncryptRTCP(nil, testCase.decryptedRTCPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.authenticatedRTCPPacket, actualEncrypted)
			})

			t.Run("Decrypt RTCP with NULL cipher", func(t *testing.T) {
				cipher, err := newSrtpCipherAeadAesGcmWithDerivedKeys(testCase.profile, testCase.keys, false, false)
				assert.NoError(t, err)
				ctx, err := createContextWithCipher(testCase.profile, cipher)
				assert.NoError(t, err)
				ctx.SetIndex(0x4d617273, 0x000005d3)

				actualDecrypted, err := ctx.DecryptRTCP(nil, testCase.authenticatedRTCPPacket, nil)
				assert.NoError(t, err)
				assert.Equal(t, testCase.decryptedRTCPPacket, actualDecrypted)
			})
		})
	}
}
