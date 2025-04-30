// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/pion/rtp"
	"github.com/pion/transport/v3/replaydetector"
	"github.com/stretchr/testify/assert"
)

const (
	profileCTR  = ProtectionProfileAes128CmHmacSha1_80
	profileGCM  = ProtectionProfileAeadAes128Gcm
	defaultSsrc = 0
)

type rtpTestCase struct {
	sequenceNumber uint16
	encryptedCTR   []byte
	encryptedGCM   []byte
}

func (tc rtpTestCase) encrypted(tb testing.TB, profile ProtectionProfile) []byte {
	tb.Helper()

	switch profile {
	case profileCTR:
		return tc.encryptedCTR
	case profileGCM:
		return tc.encryptedGCM
	default:
		assert.Fail(tb, "Invalid profile")

		return nil
	}
}

func testKeyLen(t *testing.T, profile ProtectionProfile) {
	t.Helper()

	keyLen, err := profile.KeyLen()
	assert.NoError(t, err)

	saltLen, err := profile.SaltLen()
	assert.NoError(t, err)

	_, err = CreateContext([]byte{}, make([]byte, saltLen), profile)
	assert.Error(t, err, "CreateContext failed with a 0 length key")

	_, err = CreateContext(make([]byte, keyLen), []byte{}, profile)
	assert.Error(t, err, "CreateContext accepted a 0 length salt")

	_, err = CreateContext(make([]byte, keyLen), make([]byte, saltLen), profile)
	assert.NoError(t, err, "CreateContext failed with valid key and salt")
}

func TestKeyLen(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testKeyLen(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testKeyLen(t, profileGCM) })
}

func TestValidPacketCounter(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	srtpSessionSalt, err := aesCmKeyDerivation(labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt))
	assert.NoError(t, err)

	s := &srtpSSRCState{ssrc: 4160032510}
	expectedCounter := []byte{
		0xcf, 0x90, 0x1e, 0xa5, 0xda, 0xd3, 0x2c, 0x15, 0x00, 0xa2, 0x24, 0xae, 0xae, 0xaf, 0x00, 0x00,
	}
	counter := generateCounter(32846, uint32(s.index>>16), s.ssrc, srtpSessionSalt) //nolint:gosec // G115
	assert.Equal(t, counter[:], expectedCounter)
}

func TestRolloverCount(t *testing.T) { //nolint:cyclop
	ssrcState := &srtpSSRCState{ssrc: defaultSsrc}

	// Set initial seqnum
	roc, diff, ovf := ssrcState.nextRolloverCount(65530)
	assert.Empty(t, roc, "Initial rollover counter must be 0")
	assert.False(t, ovf, "Should not overflow")

	ssrcState.updateRolloverCount(65530, diff, false, 0)

	// Invalid packets never update ROC
	ssrcState.nextRolloverCount(0)
	ssrcState.nextRolloverCount(0x4000)
	ssrcState.nextRolloverCount(0x8000)
	ssrcState.nextRolloverCount(0xFFFF)
	ssrcState.nextRolloverCount(0)

	// We rolled over to 0
	roc, diff, ovf = ssrcState.nextRolloverCount(0)
	assert.Equal(t, uint32(1), roc, "rolloverCounter must be incremented after wrapping")
	assert.False(t, ovf, "Should not overflow")

	ssrcState.updateRolloverCount(0, diff, false, 0)

	roc, diff, ovf = ssrcState.nextRolloverCount(65530)
	assert.Empty(t, roc, "rolloverCounter was not updated when it rolled back, failed to handle out of order")
	assert.False(t, ovf, "Should not overflow")

	ssrcState.updateRolloverCount(65530, diff, false, 0)

	roc, diff, ovf = ssrcState.nextRolloverCount(5)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was not updated when it rolled over initial, to handle out of order")
	assert.False(t, ovf, "Should not overflow")

	ssrcState.updateRolloverCount(5, diff, false, 0)

	_, diff, _ = ssrcState.nextRolloverCount(6)
	ssrcState.updateRolloverCount(6, diff, false, 0)
	_, diff, _ = ssrcState.nextRolloverCount(7)
	ssrcState.updateRolloverCount(7, diff, false, 0)
	roc, diff, _ = ssrcState.nextRolloverCount(8)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was improperly updated for non-significant packets")

	ssrcState.updateRolloverCount(8, diff, false, 0)

	// valid packets never update ROC
	roc, diff, ovf = ssrcState.nextRolloverCount(0x4000)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	ssrcState.updateRolloverCount(0x4000, diff, false, 0)
	roc, diff, ovf = ssrcState.nextRolloverCount(0x8000)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	ssrcState.updateRolloverCount(0x8000, diff, false, 0)
	roc, diff, ovf = ssrcState.nextRolloverCount(0xFFFF)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	ssrcState.updateRolloverCount(0xFFFF, diff, false, 0)
	roc, _, ovf = ssrcState.nextRolloverCount(0)
	assert.Equal(t, uint32(2), roc, "rolloverCounter must be incremented after wrapping")
	assert.False(t, ovf, "Should not overflow")
}

func TestRolloverCountOverflow(t *testing.T) {
	s := &srtpSSRCState{
		ssrc:  defaultSsrc,
		index: maxROC << 16,
	}
	s.updateRolloverCount(0xFFFF, 0, false, 0)
	_, _, ovf := s.nextRolloverCount(0)
	assert.True(t, ovf, "Should overflow")
}

func buildTestContext(profile ProtectionProfile, opts ...ContextOption) (*Context, error) {
	keyLen, err := profile.KeyLen()
	if err != nil {
		return nil, err
	}
	saltLen, err := profile.SaltLen()
	if err != nil {
		return nil, err
	}

	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterKey = masterKey[:keyLen]
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}
	masterSalt = masterSalt[:saltLen]

	return CreateContext(masterKey, masterSalt, profile, opts...)
}

func TestRTPInvalidAuth(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	invalidSalt := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	encryptContext, err := buildTestContext(profileCTR)
	assert.NoError(t, err)

	invalidContext, err := CreateContext(masterKey, invalidSalt, profileCTR)
	assert.NoError(t, err)

	for _, testCase := range rtpTestCases() {
		pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		pktRaw, err := pkt.Marshal()
		assert.NoError(t, err)

		out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
		assert.NoError(t, err)

		_, err = invalidContext.DecryptRTP(nil, out, nil)
		assert.Errorf(t, err, "Managed to decrypt with incorrect salt for packet with SeqNum: %d", testCase.sequenceNumber)
	}
}

func rtpTestCaseDecrypted() []byte { return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05} }

func rtpTestCases() []rtpTestCase {
	return []rtpTestCase{
		{
			sequenceNumber: 5000,
			encryptedCTR:   []byte{0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb, 0xfd, 0x8},
			encryptedGCM: []byte{
				0x05, 0x39, 0x62, 0xbb, 0x50, 0x2a, 0x08, 0x19, 0xc7, 0xcc, 0xc9,
				0x24, 0xb8, 0xd9, 0x7a, 0xe5, 0xad, 0x99, 0x06, 0xc7, 0x3b, 0x00,
			},
		},
		{
			sequenceNumber: 5001,
			encryptedCTR: []byte{
				0xda, 0x47, 0x0b, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc,
				0x4b, 0x6d, 0x23, 0xf3, 0xde,
			},
			encryptedGCM: []byte{
				0xb0, 0xbc, 0xfc, 0xb0, 0x15, 0x2c, 0xa0, 0x15, 0xb5, 0xa8, 0xcd,
				0x0d, 0x65, 0xfa, 0x98, 0xb3, 0x09, 0xb1, 0xf8, 0x4b, 0x1c, 0xfa,
			},
		},
		{
			sequenceNumber: 5002,
			encryptedCTR: []byte{
				0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x02, 0x1c,
				0xd1, 0x60, 0x76, 0xc1, 0xe,
			},
			encryptedGCM: []byte{
				0x5e, 0x20, 0x6a, 0xbf, 0x58, 0x7e, 0x24, 0xc0, 0x15, 0x94, 0x7a,
				0xe2, 0x49, 0x25, 0xd4, 0xd4, 0x08, 0xe2, 0xf1, 0x47, 0x7a, 0x33,
			},
		},
		{
			sequenceNumber: 5003,
			encryptedCTR: []byte{
				0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d,
				0xe0, 0x76, 0x9f, 0x8, 0xdc,
			},
			encryptedGCM: []byte{
				0xb0, 0x63, 0x14, 0xe7, 0xd2, 0x29, 0xca, 0x92, 0x8c, 0x97, 0x25,
				0xd2, 0x50, 0x69, 0x6e, 0x1b, 0x04, 0xb9, 0x37, 0xa5, 0xa1, 0xc5,
			},
		},
		{
			sequenceNumber: 5004,
			encryptedCTR: []byte{
				0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b,
				0x12, 0x68, 0xb, 0x57, 0x49,
			},
			encryptedGCM: []byte{
				0xb2, 0x4f, 0x19, 0x53, 0x79, 0x8a, 0x9b, 0x9e, 0xe5, 0x22, 0x93,
				0x14, 0x50, 0x8a, 0x8c, 0xd5, 0xfc, 0x61, 0xbf, 0x95, 0xd1, 0xfb,
			},
		},
		{
			sequenceNumber: 65535, // upper boundary
			encryptedCTR: []byte{
				0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85,
				0x15, 0xe, 0x44, 0xca, 0x36,
			},
			encryptedGCM: []byte{
				0x40, 0x44, 0x6c, 0xd1, 0x33, 0x5f, 0xca, 0x9b, 0x2e, 0xa3, 0xe5,
				0x03, 0xd7, 0x82, 0x36, 0xd8, 0xb7, 0xe8, 0x97, 0x3c, 0xe6, 0xb6,
			},
		},
	}
}

func testRTPLifecyleNewAlloc(t *testing.T, profile ProtectionProfile) {
	t.Helper()
	assertT := assert.New(t)

	authTagLen, err := profile.AuthTagRTPLen()
	assertT.NoError(err)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		assertT.NoError(err)

		decryptContext, err := buildTestContext(profile)
		assertT.NoError(err)

		decryptedPkt := &rtp.Packet{
			Payload: rtpTestCaseDecrypted(),
			Header:  rtp.Header{SequenceNumber: testCase.sequenceNumber},
		}
		decryptedRaw, err := decryptedPkt.Marshal()
		assertT.NoError(err)

		encryptedPkt := &rtp.Packet{
			Payload: testCase.encrypted(t, profile),
			Header:  rtp.Header{SequenceNumber: testCase.sequenceNumber},
		}
		encryptedRaw, err := encryptedPkt.Marshal()
		assertT.NoError(err)

		actualEncrypted, err := encryptContext.EncryptRTP(nil, decryptedRaw, nil)
		assertT.NoError(err)
		assertT.Equalf(actualEncrypted, encryptedRaw,
			"RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		actualDecrypted, err := decryptContext.DecryptRTP(nil, encryptedRaw, nil)
		assertT.NoError(err)
		assertT.NotEqual(encryptedRaw[:len(encryptedRaw)-authTagLen], actualDecrypted,
			"DecryptRTP improperly encrypted in place")
		assertT.Equalf(actualDecrypted, decryptedRaw,
			"RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPLifecycleNewAlloc(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPLifecyleNewAlloc(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPLifecyleNewAlloc(t, profileGCM) })
}

func testRTPLifecyleInPlace(t *testing.T, profile ProtectionProfile) { //nolint:cyclop
	t.Helper()
	assertT := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		assertT.NoError(err)

		decryptContext, err := buildTestContext(profile)
		assertT.NoError(err)

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{
			Payload: rtpTestCaseDecrypted(),
			Header:  rtp.Header{SequenceNumber: testCase.sequenceNumber},
		}
		decryptedRaw, err := decryptedPkt.Marshal()
		assertT.NoError(err)

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{
			Payload: testCase.encrypted(t, profile),
			Header:  rtp.Header{SequenceNumber: testCase.sequenceNumber},
		}
		encryptedRaw, err := encryptedPkt.Marshal()
		assertT.NoError(err)

		// Copy packet, asserts that everything was done in place
		slack := 10
		if profile == profileGCM {
			slack = 16
		}
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+slack)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		assertT.NoError(err)
		assertT.Same(&encryptInput[0], &actualEncrypted[0], "DecryptRTP failed to decrypt in place")
		assertT.Equal(testCase.sequenceNumber, encryptHeader.SequenceNumber, "EncryptRTP failed to populate input rtp.Header")
		assertT.Equalf(actualEncrypted, encryptedRaw,
			"RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		assertT.NoError(err)
		assertT.Same(&decryptInput[0], &actualDecrypted[0], "DecryptRTP failed to decrypt in place")
		assertT.Equal(testCase.sequenceNumber, decryptHeader.SequenceNumber, "DecryptRTP failed to populate input rtp.Header")
		assertT.Equalf(actualDecrypted, decryptedRaw,
			"RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPLifecycleInPlace(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPLifecyleInPlace(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPLifecyleInPlace(t, profileGCM) })
}

func testRTPReplayProtection(t *testing.T, profile ProtectionProfile) { //nolint:cyclop
	t.Helper()
	assertT := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		assertT.NoError(err)

		decryptContext, err := buildTestContext(
			profile, SRTPReplayProtection(64),
		)
		assertT.NoError(err)

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{
			Payload: rtpTestCaseDecrypted(),
			Header:  rtp.Header{SequenceNumber: testCase.sequenceNumber},
		}
		decryptedRaw, err := decryptedPkt.Marshal()
		assertT.NoError(err)

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{
			Payload: testCase.encrypted(t, profile),
			Header:  rtp.Header{SequenceNumber: testCase.sequenceNumber},
		}
		encryptedRaw, err := encryptedPkt.Marshal()
		assertT.NoError(err)

		// Copy packet, asserts that everything was done in place
		slack := 10
		if profile == profileGCM {
			slack = 16
		}
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+slack)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		assertT.NoError(err)
		assertT.Same(&encryptInput[0], &actualEncrypted[0], "EncryptRTP failed to encrypt in place")
		assertT.Equal(testCase.sequenceNumber, encryptHeader.SequenceNumber, "EncryptRTP failed to populate input rtp.Header")
		assertT.Equalf(actualEncrypted, encryptedRaw,
			"RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		assertT.NoError(err)
		assertT.Same(&decryptInput[0], &actualDecrypted[0], "DecryptRTP failed to decrypt in place")
		assertT.Equal(testCase.sequenceNumber, decryptHeader.SequenceNumber, "DecryptRTP failed to populate input rtp.Header")
		assertT.Equalf(actualDecrypted, decryptedRaw,
			"RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)

		_, errReplay := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		assertT.ErrorIs(errReplay, errDuplicated)
	}
}

func TestRTPReplayProtection(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPReplayProtection(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPReplayProtection(t, profileGCM) })
}

func TestRTPReplayDetectorFactory(t *testing.T) {
	assertT := assert.New(t)
	profile := profileCTR
	data := rtpTestCases()[0]

	var cntFactory int
	decryptContext, err := buildTestContext(
		profile, SRTPReplayDetectorFactory(func() replaydetector.ReplayDetector {
			cntFactory++

			return &nopReplayDetector{}
		}),
	)
	assertT.NoError(err)

	pkt := &rtp.Packet{
		Payload: data.encrypted(t, profile),
		Header:  rtp.Header{SequenceNumber: data.sequenceNumber},
	}
	in, err := pkt.Marshal()
	assertT.NoError(err)

	_, err = decryptContext.DecryptRTP(nil, in, nil)
	assertT.NoError(err)
	assertT.Equal(1, cntFactory)
}

func benchmarkEncryptRTP(b *testing.B, profile ProtectionProfile, size int) {
	b.Helper()

	encryptContext, err := buildTestContext(profile)
	assert.NoError(b, err)

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	assert.NoError(b, err)

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = encryptContext.EncryptRTP(nil, pktRaw, nil)
		assert.NoError(b, err)
	}
}

func BenchmarkEncryptRTP(b *testing.B) {
	b.Run("CTR-100", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileCTR, 100)
	})
	b.Run("CTR-1000", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileCTR, 1000)
	})
	b.Run("GCM-100", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileGCM, 100)
	})
	b.Run("GCM-1000", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileGCM, 1000)
	})
}

func benchmarkEncryptRTPInPlace(b *testing.B, profile ProtectionProfile, size int) {
	b.Helper()

	encryptContext, err := buildTestContext(profile)
	assert.NoError(b, err)

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	assert.NoError(b, err)

	buf := make([]byte, 0, len(pktRaw)+10)

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf, err = encryptContext.EncryptRTP(buf[:0], pktRaw, nil)
		assert.NoError(b, err)
	}
}

func BenchmarkEncryptRTPInPlace(b *testing.B) {
	b.Run("CTR-100", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileCTR, 100)
	})
	b.Run("CTR-1000", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileCTR, 1000)
	})
	b.Run("GCM-100", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileGCM, 100)
	})
	b.Run("GCM-1000", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileGCM, 1000)
	})
}

func benchmarkDecryptRTP(b *testing.B, profile ProtectionProfile) {
	b.Helper()

	sequenceNumber := uint16(5000)
	encrypted := rtpTestCases()[0].encrypted(b, profile)

	encryptedPkt := &rtp.Packet{
		Payload: encrypted,
		Header: rtp.Header{
			SequenceNumber: sequenceNumber,
		},
	}

	encryptedRaw, err := encryptedPkt.Marshal()
	assert.NoError(b, err)

	context, err := buildTestContext(profile)
	assert.NoError(b, err)

	b.SetBytes(int64(len(encryptedRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := context.DecryptRTP(nil, encryptedRaw, nil)
		assert.NoError(b, err)
	}
}

func BenchmarkDecryptRTP(b *testing.B) {
	b.Run("CTR", func(b *testing.B) { benchmarkDecryptRTP(b, profileCTR) })
	b.Run("GCM", func(b *testing.B) { benchmarkDecryptRTP(b, profileGCM) })
}

func TestRolloverCount2(t *testing.T) { //nolint:cyclop
	srtpState := &srtpSSRCState{ssrc: defaultSsrc}

	roc, diff, ovf := srtpState.nextRolloverCount(30123)
	assert.Equal(t, uint32(0), roc, "Initial rolloverCounter must be 0")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(30123, diff, false, 0)

	roc, diff, ovf = srtpState.nextRolloverCount(62892) // 30123 + (1 << 15) + 1
	assert.Equal(t, uint32(0), roc, "Initial rolloverCounter must be 0")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(62892, diff, false, 0)
	roc, diff, ovf = srtpState.nextRolloverCount(204)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was not updated after it crossed 0")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(62892, diff, false, 0)
	roc, diff, ovf = srtpState.nextRolloverCount(64535)
	assert.Equal(t, uint32(0), roc, "rolloverCounter was not updated when it rolled back, failed to handle out of order")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(64535, diff, false, 0)
	roc, diff, ovf = srtpState.nextRolloverCount(205)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(205, diff, false, 0)
	roc, diff, ovf = srtpState.nextRolloverCount(1)
	assert.Equal(t, uint32(1), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(1, diff, false, 0)

	roc, diff, ovf = srtpState.nextRolloverCount(64532)
	assert.Equal(t, uint32(0), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(64532, diff, false, 0)
	roc, diff, ovf = srtpState.nextRolloverCount(65534)
	assert.Equal(t, uint32(0), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(65534, diff, false, 0)
	roc, diff, ovf = srtpState.nextRolloverCount(64532)
	assert.Equal(t, uint32(0), roc, "rolloverCounter was improperly updated for non-significant packets")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(65532, diff, false, 0)
	roc, diff, ovf = srtpState.nextRolloverCount(205)
	assert.Equal(t, uint32(1), roc, "index was not updated after it crossed 0")
	assert.False(t, ovf, "Should not overflow")

	srtpState.updateRolloverCount(65532, diff, false, 0)
}

func TestProtectionProfileAes128CmHmacSha1_32(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	encryptContext, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
	assert.NoError(t, err)

	decryptContext, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
	assert.NoError(t, err)

	pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: 5000}}
	pktRaw, err := pkt.Marshal()
	assert.NoError(t, err)

	out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
	assert.NoError(t, err)

	decrypted, err := decryptContext.DecryptRTP(nil, out, nil)
	assert.NoError(t, err)

	assert.Equal(t, pktRaw, decrypted, "Decrypted RTP packet does not match original")
}

func TestRTPDecryptShotenedPacket(t *testing.T) {
	profiles := map[string]ProtectionProfile{
		"CTR": profileCTR,
		"GCM": profileGCM,
	}
	for name, profile := range profiles {
		profile := profile
		t.Run(name, func(t *testing.T) {
			for _, testCase := range rtpTestCases() {
				decryptContext, err := buildTestContext(profile)
				assert.NoError(t, err)

				encryptedPkt := &rtp.Packet{
					Payload: testCase.encrypted(t, profile),
					Header:  rtp.Header{SequenceNumber: testCase.sequenceNumber},
				}
				encryptedRaw, err := encryptedPkt.Marshal()
				assert.NoError(t, err)

				for i := 1; i < len(encryptedRaw)-1; i++ {
					packet := encryptedRaw[:i]
					assert.NotPanics(t, func() {
						_, _ = decryptContext.DecryptRTP(nil, packet, nil)
					}, "Panic on length %d/%d", i, len(encryptedRaw))
				}
			}
		})
	}
}

func TestRTPMaxPackets(t *testing.T) {
	profiles := map[string]ProtectionProfile{
		"CTR": profileCTR,
		"GCM": profileGCM,
	}
	for name, profile := range profiles {
		profile := profile
		t.Run(name, func(t *testing.T) {
			context, err := buildTestContext(profile)
			assert.NoError(t, err)

			context.SetROC(1, (1<<32)-1)

			pkt0 := &rtp.Packet{
				Header: rtp.Header{
					SSRC:           1,
					SequenceNumber: 0xffff,
				},
				Payload: []byte{0, 1},
			}
			raw0, err0 := pkt0.Marshal()
			assert.NoError(t, err0)

			_, errEnc := context.EncryptRTP(nil, raw0, nil)
			assert.NoError(t, errEnc)

			pkt1 := &rtp.Packet{
				Header: rtp.Header{
					SSRC:           1,
					SequenceNumber: 0x0,
				},
				Payload: []byte{0, 1},
			}
			raw1, err1 := pkt1.Marshal()
			assert.NoError(t, err1)

			_, errEnc = context.EncryptRTP(nil, raw1, nil)
			assert.ErrorIs(t, errEnc, errExceededMaxPackets)
		})
	}
}

func TestRTPBurstLossWithSetROC(t *testing.T) { //nolint:cyclop
	profiles := map[string]ProtectionProfile{
		"CTR": profileCTR,
		"GCM": profileGCM,
	}
	for name, profile := range profiles {
		profile := profile
		t.Run(name, func(t *testing.T) {
			assertT := assert.New(t)

			encryptContext, err := buildTestContext(profile)
			assertT.NoError(err)

			type packetWithROC struct {
				pkt rtp.Packet
				enc []byte
				raw []byte

				roc uint32
			}

			var pkts []*packetWithROC
			encryptContext.SetROC(1, 3)
			for i := 0x8C00; i < 0x20400; i += 0x100 {
				packet := &packetWithROC{
					pkt: rtp.Packet{
						Payload: []byte{
							byte(i >> 16),
							byte(i >> 8),
							byte(i),
						},
						Header: rtp.Header{
							Marker:         true,
							SSRC:           1,
							SequenceNumber: uint16(i), //nolint:gosec // G115
						},
					},
				}
				b, errMarshal := packet.pkt.Marshal()
				assertT.NoError(errMarshal)

				packet.raw = b
				enc, errEnc := encryptContext.EncryptRTP(nil, b, nil)
				assertT.NoError(errEnc)

				packet.roc, _ = encryptContext.ROC(1)
				if 0x9000 < i && i < 0x20100 {
					continue
				}
				packet.enc = enc
				pkts = append(pkts, packet)
			}

			decryptContext, err := buildTestContext(profile)
			assertT.NoError(err)

			for _, p := range pkts {
				decryptContext.SetROC(1, p.roc)
				pkt, err := decryptContext.DecryptRTP(nil, p.enc, nil)
				assertT.NoErrorf(err, "roc=%d, seq=%d", p.roc, p.pkt.SequenceNumber)
				assertT.Equal(p.raw, pkt)
			}
		})
	}
}

func TestDecryptInvalidSRTP(t *testing.T) {
	assertT := assert.New(t)
	key := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	salt := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	decryptContext, err := CreateContext(key, salt, ProtectionProfileAes128CmHmacSha1_80)
	assertT.NoError(err)

	packet := []byte{
		0x41, 0x02, 0x07, 0xf9, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xb5, 0x73, 0x19, 0xf6, 0x91, 0xbb, 0x3e, 0xa5, 0x21, 0x07,
	}
	_, err = decryptContext.DecryptRTP(nil, packet, nil)
	assertT.Error(err)
}

func TestRTPInvalidMKI(t *testing.T) {
	mki1 := []byte{0x01, 0x02, 0x03, 0x04}
	mki2 := []byte{0x02, 0x03, 0x04, 0x05}

	encryptContext, err := buildTestContext(profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	decryptContext, err := buildTestContext(profileCTR, MasterKeyIndicator(mki2))
	assert.NoError(t, err)

	for _, testCase := range rtpTestCases() {
		pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		pktRaw, err := pkt.Marshal()
		assert.NoError(t, err)

		out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
		assert.NoError(t, err)

		_, err = decryptContext.DecryptRTP(nil, out, nil)
		assert.Errorf(t, err, "Managed to decrypt with incorrect MKI for packet with SeqNum: %d", testCase.sequenceNumber)
		assert.ErrorIs(t, err, ErrMKINotFound)
	}
}

func TestRTPHandleMultipleMKI(t *testing.T) { //nolint:cyclop
	mki1 := []byte{0x01, 0x02, 0x03, 0x04}
	mki2 := []byte{0x02, 0x03, 0x04, 0x05}

	masterKey2 := []byte{0xff, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt2 := []byte{0xff, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	encryptContext1, err := buildTestContext(profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	encryptContext2, err := CreateContext(masterKey2, masterSalt2, profileCTR, MasterKeyIndicator(mki2))
	assert.NoError(t, err)

	decryptContext, err := buildTestContext(profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	err = decryptContext.AddCipherForMKI(mki2, masterKey2, masterSalt2)
	assert.NoError(t, err)

	for _, testCase := range rtpTestCases() {
		pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		pktRaw, err := pkt.Marshal()
		assert.NoError(t, err)

		encrypted1, err := encryptContext1.EncryptRTP(nil, pktRaw, nil)
		assert.NoError(t, err)

		encrypted2, err := encryptContext2.EncryptRTP(nil, pktRaw, nil)
		assert.NoError(t, err)

		decrypted1, err := decryptContext.DecryptRTP(nil, encrypted1, nil)
		assert.NoError(t, err)

		decrypted2, err := decryptContext.DecryptRTP(nil, encrypted2, nil)
		assert.NoError(t, err)

		assert.Equal(t, pktRaw, decrypted1)
		assert.Equal(t, pktRaw, decrypted2)
	}
}

func TestRTPSwitchMKI(t *testing.T) { //nolint:cyclop
	mki1 := []byte{0x01, 0x02, 0x03, 0x04}
	mki2 := []byte{0x02, 0x03, 0x04, 0x05}

	masterKey2 := []byte{0xff, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt2 := []byte{0xff, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	encryptContext, err := buildTestContext(profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	err = encryptContext.AddCipherForMKI(mki2, masterKey2, masterSalt2)
	assert.NoError(t, err)

	decryptContext1, err := buildTestContext(profileCTR, MasterKeyIndicator(mki1))
	assert.NoError(t, err)

	decryptContext2, err := CreateContext(masterKey2, masterSalt2, profileCTR, MasterKeyIndicator(mki2))
	assert.NoError(t, err)

	for _, testCase := range rtpTestCases() {
		pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		pktRaw, err := pkt.Marshal()
		assert.NoError(t, err)

		encrypted1, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
		assert.NoError(t, err)

		err = encryptContext.SetSendMKI(mki2)
		assert.NoError(t, err)

		encrypted2, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
		assert.NoError(t, err)

		assert.NotEqual(t, encrypted1, encrypted2)

		decrypted1, err := decryptContext1.DecryptRTP(nil, encrypted1, nil)
		assert.NoError(t, err)

		decrypted2, err := decryptContext2.DecryptRTP(nil, encrypted2, nil)
		assert.NoError(t, err)

		assert.Equal(t, pktRaw, decrypted1)
		assert.Equal(t, pktRaw, decrypted2)

		err = encryptContext.SetSendMKI(mki1)
		assert.NoError(t, err)
	}
}
