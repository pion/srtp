// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func addMkiToAesPacket(packet, mki []byte, authTagLen int) []byte {
	p := make([]byte, len(packet)+len(mki))
	copy(p, packet[:len(packet)-authTagLen])
	copy(p[len(packet)-authTagLen:], mki)
	copy(p[len(packet)-authTagLen+len(mki):], packet[len(packet)-authTagLen:])
	return p
}

func TestSrtpCipherAes128CmHmacSha1_32(t *testing.T) {
	decryptedRTPPacket := []byte{
		0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
		0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab,
	}
	encryptedRTPPacket := []byte{
		0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
		0xca, 0xfe, 0xba, 0xbe, 0xe2, 0xd8, 0xdf, 0x8f,
		0x7a, 0x75, 0xd6, 0x88, 0xc3, 0x50, 0x2e, 0xee,
		0xc2, 0xa9, 0x80, 0x66, 0xcd, 0x7c, 0x0d, 0x09,
	}
	decryptedRtcpPacket := []byte{
		0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	}
	encryptedRtcpPacket := []byte{
		0x81, 0xc8, 0x0, 0x00b, 0xca, 0xfe, 0xba, 0xbe,
		0x56, 0x74, 0xbf, 0x01, 0x81, 0x3d, 0xc0, 0x62,
		0xac, 0x1d, 0xf6, 0xf7, 0x5f, 0x77, 0xc6, 0x88,
		0x80, 0x00, 0x00, 0x01, 0x3d, 0xb7, 0xa1, 0x98,
		0x37, 0xff, 0x64, 0xe5, 0xcb, 0xd2,
	}

	masterKey := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	masterSalt := []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0x0ac, 0xad}

	mki := []byte{0x01, 0x02, 0x03, 0x04}

	t.Run("Encrypt RTP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTP(nil, decryptedRTPPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, encryptedRTPPacket, actualEncrypted)
		})
	})

	t.Run("Decrypt RTP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTP(nil, encryptedRTPPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRTPPacket, actualDecrypted)
		})
	})

	t.Run("Encrypt RTP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTP(nil, decryptedRTPPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, addMkiToAesPacket(encryptedRTPPacket, mki, 4), actualEncrypted)
		})
	})

	t.Run("Decrypt RTP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTP(nil, addMkiToAesPacket(encryptedRTPPacket, mki, 4), nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRTPPacket, actualDecrypted)
		})
	})

	t.Run("Encrypt RTCP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTCP(nil, decryptedRtcpPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, encryptedRtcpPacket, actualEncrypted)
		})
	})

	t.Run("Decrypt RTCP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTCP(nil, encryptedRtcpPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRtcpPacket, actualDecrypted)
		})
	})

	t.Run("Encrypt RTCP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTCP(nil, decryptedRtcpPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, addMkiToAesPacket(encryptedRtcpPacket, mki, 10), actualEncrypted)
		})
	})

	t.Run("Decrypt RTCP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTCP(nil, addMkiToAesPacket(encryptedRtcpPacket, mki, 10), nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRtcpPacket, actualDecrypted)
		})
	})
}

func TestSrtpCipherAes128CmHmacSha1_80(t *testing.T) {
	decryptedRTPPacket := []byte{
		0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
		0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab,
	}
	encryptedRTPPacket := []byte{
		0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
		0xca, 0xfe, 0xba, 0xbe, 0xe2, 0xd8, 0xdf, 0x8f,
		0x7a, 0x75, 0xd6, 0x88, 0xc3, 0x50, 0x2e, 0xee,
		0xc2, 0xa9, 0x80, 0x66, 0xcd, 0x7c, 0x0d, 0x09,
		0xca, 0x44, 0x32, 0xa5, 0x6e, 0x3d,
	}
	decryptedRtcpPacket := []byte{
		0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	}
	encryptedRtcpPacket := []byte{
		0x81, 0xc8, 0x0, 0x00b, 0xca, 0xfe, 0xba, 0xbe,
		0x56, 0x74, 0xbf, 0x01, 0x81, 0x3d, 0xc0, 0x62,
		0xac, 0x1d, 0xf6, 0xf7, 0x5f, 0x77, 0xc6, 0x88,
		0x80, 0x00, 0x00, 0x01, 0x3d, 0xb7, 0xa1, 0x98,
		0x37, 0xff, 0x64, 0xe5, 0xcb, 0xd2,
	}

	masterKey := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	masterSalt := []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0x0ac, 0xad}

	mki := []byte{0x01, 0x02, 0x03, 0x04}

	t.Run("Encrypt RTP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTP(nil, decryptedRTPPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, encryptedRTPPacket, actualEncrypted)
		})
	})

	t.Run("Decrypt RTP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTP(nil, encryptedRTPPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRTPPacket, actualDecrypted)
		})
	})

	t.Run("Encrypt RTP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTP(nil, decryptedRTPPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, addMkiToAesPacket(encryptedRTPPacket, mki, 10), actualEncrypted)
		})
	})

	t.Run("Decrypt RTP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTP(nil, addMkiToAesPacket(encryptedRTPPacket, mki, 10), nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRTPPacket, actualDecrypted)
		})
	})

	t.Run("Encrypt RTCP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTCP(nil, decryptedRtcpPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, encryptedRtcpPacket, actualEncrypted)
		})
	})

	t.Run("Decrypt RTCP", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80)
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTCP(nil, encryptedRtcpPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRtcpPacket, actualDecrypted)
		})
	})

	t.Run("Encrypt RTCP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualEncrypted, err := ctx.EncryptRTCP(nil, decryptedRtcpPacket, nil)
			assert.NoError(t, err)
			assert.Equal(t, addMkiToAesPacket(encryptedRtcpPacket, mki, 10), actualEncrypted)
		})
	})

	t.Run("Decrypt RTCP with MKI", func(t *testing.T) {
		ctx, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_80, MasterKeyIndicator(mki))
		assert.NoError(t, err)

		t.Run("New Allocation", func(t *testing.T) {
			actualDecrypted, err := ctx.DecryptRTCP(nil, addMkiToAesPacket(encryptedRtcpPacket, mki, 10), nil)
			assert.NoError(t, err)
			assert.Equal(t, decryptedRtcpPacket, actualDecrypted)
		})
	})
}
