package srtp

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/pion/rtcp"
	"github.com/stretchr/testify/assert"
)

var (
	rtcpTestMasterKey  = []byte{0xfd, 0xa6, 0x25, 0x95, 0xd7, 0xf6, 0x92, 0x6f, 0x7d, 0x9c, 0x02, 0x4c, 0xc9, 0x20, 0x9f, 0x34}
	rtcpTestMasterSalt = []byte{0xa9, 0x65, 0x19, 0x85, 0x54, 0x0b, 0x47, 0xbe, 0x2f, 0x27, 0xa8, 0xb8, 0x81, 0x23}

	rtcpTestEncrypted  = []byte{0x80, 0xc8, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0xcd, 0x34, 0xc5, 0x78, 0xb2, 0x8b, 0xe1, 0x6b, 0xc5, 0x09, 0xd5, 0x77, 0xe4, 0xce, 0x5f, 0x20, 0x80, 0x21, 0xbd, 0x66, 0x74, 0x65, 0xe9, 0x5f, 0x49, 0xe5, 0xf5, 0xc0, 0x68, 0x4e, 0xe5, 0x6a, 0x78, 0x07, 0x75, 0x46, 0xed, 0x90, 0xf6, 0xdc, 0x9d, 0xef, 0x3b, 0xdf, 0xf2, 0x79, 0xa9, 0xd8, 0x80, 0x00, 0x00, 0x01, 0x60, 0xc0, 0xae, 0xb5, 0x6f, 0x40, 0x88, 0x0e, 0x28, 0xba}
	rtcpTestEncrypted2 = []byte{0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x17, 0x8c, 0x15, 0xf1, 0x4b, 0x11, 0xda, 0xf5, 0x74, 0x53, 0x86, 0x2b, 0xc9, 0x07, 0x29, 0x40, 0xbf, 0x22, 0xf6, 0x46, 0x11, 0xa4, 0xc1, 0x3a, 0xff, 0x5a, 0xbd, 0xd0, 0xf8, 0x8b, 0x38, 0xe4, 0x95, 0x38, 0x5d, 0xcf, 0x1b, 0xf5, 0x27, 0x77, 0xfb, 0xdb, 0x3f, 0x10, 0x68, 0x99, 0xd8, 0xad, 0x80, 0x00, 0x00, 0x01, 0x34, 0x3c, 0x2e, 0x83, 0x17, 0x13, 0x93, 0x69, 0xcf, 0xc0}
	rtcpTestDecrypted  = []byte{0x80, 0xc8, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0xdf, 0x48, 0x80, 0xdd, 0x61, 0xa6, 0x2e, 0xd3, 0xd8, 0xbc, 0xde, 0xbe, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x16, 0x04, 0x81, 0xca, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0x01, 0x10, 0x52, 0x6e, 0x54, 0x35, 0x43, 0x6d, 0x4a, 0x68, 0x7a, 0x79, 0x65, 0x74, 0x41, 0x78, 0x77, 0x2b, 0x00, 0x00}
	rtcpTestDecrypted2 = []byte{0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0xdf, 0x48, 0x80, 0xdd, 0x61, 0xa6, 0x2e, 0xd3, 0xd8, 0xbc, 0xde, 0xbe, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x16, 0x04, 0x81, 0xca, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0x01, 0x10, 0x52, 0x6e, 0x54, 0x35, 0x43, 0x6d, 0x4a, 0x68, 0x7a, 0x79, 0x65, 0x74, 0x41, 0x78, 0x77, 0x2b, 0x00, 0x00}
)

func TestRTCPLifecycle(t *testing.T) {
	assert := assert.New(t)
	encryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	decryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	decryptResult, err := decryptContext.DecryptRTCP(nil, rtcpTestEncrypted, nil)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(decryptResult, rtcpTestDecrypted, "RTCP failed to decrypt")

	encryptResult, err := encryptContext.EncryptRTCP(nil, rtcpTestDecrypted, nil)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(encryptResult, rtcpTestEncrypted, "RTCP failed to encrypt")
}

func TestRTCPLifecycleInPlace(t *testing.T) {
	assert := assert.New(t)
	authTagLen, err := ProtectionProfileAes128CmHmacSha1_80.authTagLen()
	assert.NoError(err)

	encryptHeader := &rtcp.Header{}
	encryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	decryptHeader := &rtcp.Header{}
	decryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	// Copy packet, asserts that everything was done in place
	decryptInput := append([]byte{}, rtcpTestEncrypted...)

	actualDecrypted, err := decryptContext.DecryptRTCP(decryptInput, decryptInput, decryptHeader)
	if err != nil {
		t.Error(err)
	} else if decryptHeader.Type != rtcp.TypeSenderReport {
		t.Fatal("DecryptRTCP failed to populate input rtcp.Header")
	} else if !bytes.Equal(decryptInput[:len(decryptInput)-(authTagLen+srtcpIndexSize)], actualDecrypted) {
		t.Fatal("DecryptRTP failed to decrypt in place")
	}

	assert.Equal(actualDecrypted, rtcpTestDecrypted, "RTCP failed to decrypt")

	// Copy packet, asserts that everything was done in place
	encryptInput := append([]byte{}, rtcpTestDecrypted...)

	actualEncrypted, err := encryptContext.EncryptRTCP(encryptInput, encryptInput, encryptHeader)
	if err != nil {
		t.Error(err)
	} else if encryptHeader.Type != rtcp.TypeSenderReport {
		t.Fatal("EncryptRTCP failed to populate input rtcp.Header")
	} else if !bytes.Equal(encryptInput, actualEncrypted[:len(actualEncrypted)-(authTagLen+srtcpIndexSize)]) {
		t.Fatal("EncryptRTCP failed to encrypt in place")
	}

	assert.Equal(actualEncrypted, rtcpTestEncrypted, "RTCP failed to encrypt")
}

// Assert that passing a dst buffer that is too short doesn't result in a failure
func TestRTCPLifecyclePartialAllocation(t *testing.T) {
	assert := assert.New(t)

	encryptHeader := &rtcp.Header{}
	encryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	decryptHeader := &rtcp.Header{}
	decryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	// Copy packet, asserts that partial buffers can be used
	decryptDst := make([]byte, len(rtcpTestDecrypted)*2)

	actualDecrypted, err := decryptContext.DecryptRTCP(decryptDst, rtcpTestEncrypted, decryptHeader)
	if err != nil {
		t.Error(err)
	} else if decryptHeader.Type != rtcp.TypeSenderReport {
		t.Fatal("DecryptRTCP failed to populate input rtcp.Header")
	}
	assert.Equal(actualDecrypted, rtcpTestDecrypted, "RTCP failed to decrypt")

	// Copy packet, asserts that partial buffers can be used
	encryptDst := make([]byte, len(rtcpTestEncrypted)/2)

	actualEncrypted, err := encryptContext.EncryptRTCP(encryptDst, rtcpTestDecrypted, encryptHeader)
	if err != nil {
		t.Error(err)
	} else if encryptHeader.Type != rtcp.TypeSenderReport {
		t.Fatal("EncryptRTCP failed to populate input rtcp.Header")
	}
	assert.Equal(actualEncrypted, rtcpTestEncrypted, "RTCP failed to encrypt")
}

func TestRTCPInvalidAuthTag(t *testing.T) {
	assert := assert.New(t)
	authTagLen, err := ProtectionProfileAes128CmHmacSha1_80.authTagLen()
	assert.NoError(err)

	decryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	rtcpPacket := append([]byte{}, rtcpTestEncrypted...)
	decryptResult, err := decryptContext.DecryptRTCP(nil, rtcpPacket, nil)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(decryptResult, rtcpTestDecrypted, "RTCP failed to decrypt")

	// Zero out auth tag
	copy(rtcpPacket[len(rtcpPacket)-authTagLen:], make([]byte, authTagLen))

	if _, err = decryptContext.DecryptRTCP(nil, rtcpPacket, nil); err == nil {
		t.Errorf("Was able to decrypt RTCP packet with invalid Auth Tag")
	}
}

func TestRTCPReplayDetectorSeparation(t *testing.T) {
	assert := assert.New(t)
	decryptContext, err := CreateContext(
		rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo,
		SRTCPReplayProtection(10),
	)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	rtcpPacket1 := append([]byte{}, rtcpTestEncrypted...)
	decryptResult1, err := decryptContext.DecryptRTCP(nil, rtcpPacket1, nil)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(decryptResult1, rtcpTestDecrypted, "RTCP failed to decrypt")

	rtcpPacket2 := append([]byte{}, rtcpTestEncrypted2...)
	decryptResult2, err := decryptContext.DecryptRTCP(nil, rtcpPacket2, nil)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(decryptResult2, rtcpTestDecrypted2, "RTCP failed to decrypt")

	if _, err = decryptContext.DecryptRTCP(nil, rtcpPacket1, nil); err != errDuplicated {
		t.Errorf("Was able to decrypt duplicated RTCP packet")
	}
	if _, err = decryptContext.DecryptRTCP(nil, rtcpPacket2, nil); err != errDuplicated {
		t.Errorf("Was able to decrypt duplicated RTCP packet")
	}
}

func getRTCPIndex(encrypted []byte, authTagLen int) uint32 {
	tailOffset := len(encrypted) - (authTagLen + srtcpIndexSize)
	srtcpIndexBuffer := encrypted[tailOffset : tailOffset+srtcpIndexSize]
	return binary.BigEndian.Uint32(srtcpIndexBuffer) &^ (1 << 31)
}

func TestEncryptRTCPSeparation(t *testing.T) {
	assert := assert.New(t)
	encryptContext, err := CreateContext(rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo)
	assert.NoError(err)

	authTagLen, err := ProtectionProfileAes128CmHmacSha1_80.authTagLen()
	assert.NoError(err)

	decryptContext, err := CreateContext(
		rtcpTestMasterKey, rtcpTestMasterSalt, cipherContextAlgo,
		SRTCPReplayProtection(10),
	)
	assert.NoError(err)

	encryptHeader := &rtcp.Header{}

	inputs := [][]byte{rtcpTestDecrypted, rtcpTestDecrypted2, rtcpTestDecrypted, rtcpTestDecrypted2}
	encryptedRCTPs := make([][]byte, len(inputs))

	for i, input := range inputs {
		encrypted, err := encryptContext.EncryptRTCP(nil, input, encryptHeader)
		assert.NoError(err)
		encryptedRCTPs[i] = encrypted
	}

	for i, expectedIndex := range []uint32{1, 1, 2, 2} {
		assert.Equal(expectedIndex, getRTCPIndex(encryptedRCTPs[i], authTagLen), "RTCP index does not match")
	}

	for i, output := range encryptedRCTPs {
		decrypted, err := decryptContext.DecryptRTCP(nil, output, encryptHeader)
		assert.NoError(err)
		assert.Equal(inputs[i], decrypted)
	}
}
