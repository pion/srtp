package srtp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/pion/rtp"
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

func (tc rtpTestCase) encrypted(profile ProtectionProfile) []byte {
	switch profile {
	case profileCTR:
		return tc.encryptedCTR
	case profileGCM:
		return tc.encryptedGCM
	default:
		panic("unknown profile")
	}
}

func testKeyLen(t *testing.T, profile ProtectionProfile) {
	keyLen, err := profile.keyLen()
	assert.NoError(t, err)

	saltLen, err := profile.saltLen()
	assert.NoError(t, err)

	if _, err := CreateContext([]byte{}, make([]byte, saltLen), profile); err == nil {
		t.Errorf("CreateContext accepted a 0 length key")
	}

	if _, err := CreateContext(make([]byte, keyLen), []byte{}, profile); err == nil {
		t.Errorf("CreateContext accepted a 0 length salt")
	}

	if _, err := CreateContext(make([]byte, keyLen), make([]byte, saltLen), profile); err != nil {
		t.Errorf("CreateContext failed with a valid length key and salt: %v", err)
	}
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
	expectedCounter := []byte{0xcf, 0x90, 0x1e, 0xa5, 0xda, 0xd3, 0x2c, 0x15, 0x00, 0xa2, 0x24, 0xae, 0xae, 0xaf, 0x00, 0x00}
	counter := generateCounter(32846, uint32(s.index>>16), s.ssrc, srtpSessionSalt)
	if !bytes.Equal(counter[:], expectedCounter) {
		t.Errorf("Session Key % 02x does not match expected % 02x", counter, expectedCounter)
	}
}

func TestRolloverCount(t *testing.T) {
	s := &srtpSSRCState{ssrc: defaultSsrc}

	// Set initial seqnum
	roc, diff, ovf := s.nextRolloverCount(65530)
	if roc != 0 {
		t.Errorf("Initial rolloverCounter must be 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65530, diff)

	// Invalid packets never update ROC
	s.nextRolloverCount(0)
	s.nextRolloverCount(0x4000)
	s.nextRolloverCount(0x8000)
	s.nextRolloverCount(0xFFFF)
	s.nextRolloverCount(0)

	// We rolled over to 0
	roc, diff, ovf = s.nextRolloverCount(0)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated after it crossed 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0, diff)

	roc, diff, ovf = s.nextRolloverCount(65530)
	if roc != 0 {
		t.Errorf("rolloverCounter was not updated when it rolled back, failed to handle out of order")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65530, diff)

	roc, diff, ovf = s.nextRolloverCount(5)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated when it rolled over initial, to handle out of order")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(5, diff)

	_, diff, _ = s.nextRolloverCount(6)
	s.updateRolloverCount(6, diff)
	_, diff, _ = s.nextRolloverCount(7)
	s.updateRolloverCount(7, diff)
	roc, diff, _ = s.nextRolloverCount(8)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	s.updateRolloverCount(8, diff)

	// valid packets never update ROC
	roc, diff, ovf = s.nextRolloverCount(0x4000)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0x4000, diff)
	roc, diff, ovf = s.nextRolloverCount(0x8000)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0x8000, diff)
	roc, diff, ovf = s.nextRolloverCount(0xFFFF)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0xFFFF, diff)
	roc, _, ovf = s.nextRolloverCount(0)
	if roc != 2 {
		t.Errorf("rolloverCounter must be incremented after wrapping, got %d", roc)
	}
	if ovf {
		t.Error("Should not overflow")
	}
}

func TestRolloverCountOverflow(t *testing.T) {
	s := &srtpSSRCState{
		ssrc:  defaultSsrc,
		index: maxROC << 16,
	}
	s.updateRolloverCount(0xFFFF, 0)
	_, _, ovf := s.nextRolloverCount(0)
	if !ovf {
		t.Error("Should overflow")
	}
}

func buildTestContext(profile ProtectionProfile, opts ...ContextOption) (*Context, error) {
	keyLen, err := profile.keyLen()
	if err != nil {
		return nil, err
	}
	saltLen, err := profile.saltLen()
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
	if err != nil {
		t.Fatal(err)
	}

	invalidContext, err := CreateContext(masterKey, invalidSalt, profileCTR)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	for _, testCase := range rtpTestCases() {
		pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		pktRaw, err := pkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := invalidContext.DecryptRTP(nil, out, nil); err == nil {
			t.Errorf("Managed to decrypt with incorrect salt for packet with SeqNum: %d", testCase.sequenceNumber)
		}
	}
}

func rtpTestCaseDecrypted() []byte { return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05} }

func rtpTestCases() []rtpTestCase {
	return []rtpTestCase{
		{
			sequenceNumber: 5000,
			encryptedCTR:   []byte{0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb, 0xfd, 0x8},
			encryptedGCM:   []byte{0x05, 0x39, 0x62, 0xbb, 0x50, 0x2a, 0x08, 0x19, 0xc7, 0xcc, 0xc9, 0x24, 0xb8, 0xd9, 0x7a, 0xe5, 0xad, 0x99, 0x06, 0xc7, 0x3b, 0},
		},
		{
			sequenceNumber: 5001,
			encryptedCTR:   []byte{0xda, 0x47, 0xb, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc, 0x4b, 0x6d, 0x23, 0xf3, 0xde},
			encryptedGCM:   []byte{0xb0, 0xbc, 0xfc, 0xb0, 0x15, 0x2c, 0xa0, 0x15, 0xb5, 0xa8, 0xcd, 0x0d, 0x65, 0xfa, 0x98, 0xb3, 0x09, 0xb1, 0xf8, 0x4b, 0x1c, 0xfa},
		},
		{
			sequenceNumber: 5002,
			encryptedCTR:   []byte{0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x2, 0x1c, 0xd1, 0x60, 0x76, 0xc1, 0xe},
			encryptedGCM:   []byte{0x5e, 0x20, 0x6a, 0xbf, 0x58, 0x7e, 0x24, 0xc0, 0x15, 0x94, 0x7a, 0xe2, 0x49, 0x25, 0xd4, 0xd4, 0x08, 0xe2, 0xf1, 0x47, 0x7a, 0x33},
		},
		{
			sequenceNumber: 5003,
			encryptedCTR:   []byte{0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d, 0xe0, 0x76, 0x9f, 0x8, 0xdc},
			encryptedGCM:   []byte{0xb0, 0x63, 0x14, 0xe7, 0xd2, 0x29, 0xca, 0x92, 0x8c, 0x97, 0x25, 0xd2, 0x50, 0x69, 0x6e, 0x1b, 0x04, 0xb9, 0x37, 0xa5, 0xa1, 0xc5},
		},
		{
			sequenceNumber: 5004,
			encryptedCTR:   []byte{0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b, 0x12, 0x68, 0xb, 0x57, 0x49},
			encryptedGCM:   []byte{0xb2, 0x4f, 0x19, 0x53, 0x79, 0x8a, 0x9b, 0x9e, 0xe5, 0x22, 0x93, 0x14, 0x50, 0x8a, 0x8c, 0xd5, 0xfc, 0x61, 0xbf, 0x95, 0xd1, 0xfb},
		},
		{
			sequenceNumber: 65535, // upper boundary
			encryptedCTR:   []byte{0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85, 0x15, 0xe, 0x44, 0xca, 0x36},
			encryptedGCM:   []byte{0x40, 0x44, 0x6c, 0xd1, 0x33, 0x5f, 0xca, 0x9b, 0x2e, 0xa3, 0xe5, 0x03, 0xd7, 0x82, 0x36, 0xd8, 0xb7, 0xe8, 0x97, 0x3c, 0xe6, 0xb6},
		},
	}
}

func testRTPLifecyleNewAlloc(t *testing.T, profile ProtectionProfile) {
	assert := assert.New(t)

	authTagLen, err := profile.rtpAuthTagLen()
	assert.NoError(err)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		actualEncrypted, err := encryptContext.EncryptRTP(nil, decryptedRaw, nil)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		actualDecrypted, err := decryptContext.DecryptRTP(nil, encryptedRaw, nil)
		if err != nil {
			t.Fatal(err)
		} else if bytes.Equal(encryptedRaw[:len(encryptedRaw)-authTagLen], actualDecrypted) {
			t.Fatal("DecryptRTP improperly encrypted in place")
		}

		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPLifecycleNewAlloc(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPLifecyleNewAlloc(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPLifecyleNewAlloc(t, profileGCM) })
}

func testRTPLifecyleInPlace(t *testing.T, profile ProtectionProfile) {
	assert := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		// Copy packet, asserts that everything was done in place
		slack := 10
		if profile == profileGCM {
			slack = 16
		}
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+slack)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &encryptInput[0] != &actualEncrypted[0]:
			t.Errorf("EncryptRTP failed to encrypt in place")
		case encryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Errorf("EncryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &decryptInput[0] != &actualDecrypted[0]:
			t.Errorf("DecryptRTP failed to decrypt in place")
		case decryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Errorf("DecryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPLifecycleInPlace(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPLifecyleInPlace(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPLifecyleInPlace(t, profileGCM) })
}

func testRTPReplayProtection(t *testing.T, profile ProtectionProfile) {
	assert := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext(
			profile, SRTPReplayProtection(64),
		)
		if err != nil {
			t.Fatal(err)
		}

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		// Copy packet, asserts that everything was done in place
		slack := 10
		if profile == profileGCM {
			slack = 16
		}
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+slack)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &encryptInput[0] != &actualEncrypted[0]:
			t.Errorf("EncryptRTP failed to encrypt in place")
		case encryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Fatal("EncryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &decryptInput[0] != &actualDecrypted[0]:
			t.Errorf("DecryptRTP failed to decrypt in place")
		case decryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Errorf("DecryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)

		_, errReplay := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		if !errors.Is(errReplay, errDuplicated) {
			t.Errorf("Replayed packet must be errored with %v, got %v", errDuplicated, errReplay)
		}
	}
}

func TestRTPReplayProtection(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPReplayProtection(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPReplayProtection(t, profileGCM) })
}

func benchmarkEncryptRTP(b *testing.B, profile ProtectionProfile, size int) {
	encryptContext, err := buildTestContext(profile)
	if err != nil {
		b.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = encryptContext.EncryptRTP(nil, pktRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
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
	encryptContext, err := buildTestContext(profile)
	if err != nil {
		b.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, 0, len(pktRaw)+10)

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf, err = encryptContext.EncryptRTP(buf[:0], pktRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
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
	sequenceNumber := uint16(5000)
	encrypted := rtpTestCases()[0].encrypted(profile)

	encryptedPkt := &rtp.Packet{
		Payload: encrypted,
		Header: rtp.Header{
			SequenceNumber: sequenceNumber,
		},
	}

	encryptedRaw, err := encryptedPkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	context, err := buildTestContext(profile)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(encryptedRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := context.DecryptRTP(nil, encryptedRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptRTP(b *testing.B) {
	b.Run("CTR", func(b *testing.B) { benchmarkDecryptRTP(b, profileCTR) })
	b.Run("GCM", func(b *testing.B) { benchmarkDecryptRTP(b, profileGCM) })
}

func TestRolloverCount2(t *testing.T) {
	s := &srtpSSRCState{ssrc: defaultSsrc}

	roc, diff, ovf := s.nextRolloverCount(30123)
	if roc != 0 {
		t.Errorf("Initial rolloverCounter must be 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(30123, diff)

	roc, diff, ovf = s.nextRolloverCount(62892) // 30123 + (1 << 15) + 1
	if roc != 0 {
		t.Errorf("Initial rolloverCounter must be 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(62892, diff)
	roc, diff, ovf = s.nextRolloverCount(204)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated after it crossed 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(62892, diff)
	roc, diff, ovf = s.nextRolloverCount(64535)
	if roc != 0 {
		t.Errorf("rolloverCounter was not updated when it rolled back, failed to handle out of order")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(64535, diff)
	roc, diff, ovf = s.nextRolloverCount(205)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(205, diff)
	roc, diff, ovf = s.nextRolloverCount(1)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(1, diff)

	roc, diff, ovf = s.nextRolloverCount(64532)
	if roc != 0 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(64532, diff)
	roc, diff, ovf = s.nextRolloverCount(65534)
	if roc != 0 {
		t.Errorf("index was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65534, diff)
	roc, diff, ovf = s.nextRolloverCount(64532)
	if roc != 0 {
		t.Errorf("index was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65532, diff)
	roc, diff, ovf = s.nextRolloverCount(205)
	if roc != 1 {
		t.Errorf("index was not updated after it crossed 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65532, diff)
}

func TestProtectionProfileAes128CmHmacSha1_32(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	encryptContext, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
	if err != nil {
		t.Fatal(err)
	}

	decryptContext, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
	if err != nil {
		t.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: 5000}}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := decryptContext.DecryptRTP(nil, out, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, pktRaw) {
		t.Errorf("Decrypted % 02x does not match original % 02x", decrypted, pktRaw)
	}
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
				if err != nil {
					t.Fatal(err)
				}

				encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
				encryptedRaw, err := encryptedPkt.Marshal()
				if err != nil {
					t.Fatal(err)
				}

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
			if err != nil {
				t.Fatal(err)
			}

			context.SetROC(1, (1<<32)-1)

			pkt0 := &rtp.Packet{
				Header: rtp.Header{
					SSRC:           1,
					SequenceNumber: 0xffff,
				},
				Payload: []byte{0, 1},
			}
			raw0, err0 := pkt0.Marshal()
			if err0 != nil {
				t.Fatal(err0)
			}
			if _, errEnc := context.EncryptRTP(nil, raw0, nil); errEnc != nil {
				t.Fatal(errEnc)
			}

			pkt1 := &rtp.Packet{
				Header: rtp.Header{
					SSRC:           1,
					SequenceNumber: 0x0,
				},
				Payload: []byte{0, 1},
			}
			raw1, err1 := pkt1.Marshal()
			if err1 != nil {
				t.Fatal(err1)
			}
			if _, errEnc := context.EncryptRTP(nil, raw1, nil); !errors.Is(errEnc, errExceededMaxPackets) {
				t.Fatalf("Expected error '%v', got '%v'", errExceededMaxPackets, errEnc)
			}
		})
	}
}

func TestRTPBurstLossWithSetROC(t *testing.T) {
	profiles := map[string]ProtectionProfile{
		"CTR": profileCTR,
		"GCM": profileGCM,
	}
	for name, profile := range profiles {
		profile := profile
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			encryptContext, err := buildTestContext(profile)
			if err != nil {
				t.Fatal(err)
			}

			type packetWithROC struct {
				pkt rtp.Packet
				enc []byte
				raw []byte

				roc uint32
			}

			var pkts []*packetWithROC
			encryptContext.SetROC(1, 3)
			for i := 0x8C00; i < 0x20400; i += 0x100 {
				p := &packetWithROC{
					pkt: rtp.Packet{
						Payload: []byte{
							byte(i >> 16),
							byte(i >> 8),
							byte(i),
						},
						Header: rtp.Header{
							Marker:         true,
							SSRC:           1,
							SequenceNumber: uint16(i),
						},
					},
				}
				b, errMarshal := p.pkt.Marshal()
				if errMarshal != nil {
					t.Fatal(errMarshal)
				}
				p.raw = b
				enc, errEnc := encryptContext.EncryptRTP(nil, b, nil)
				if errEnc != nil {
					t.Fatal(errEnc)
				}
				p.roc, _ = encryptContext.ROC(1)
				if 0x9000 < i && i < 0x20100 {
					continue
				}
				p.enc = enc
				pkts = append(pkts, p)
			}

			decryptContext, err := buildTestContext(profile)
			if err != nil {
				t.Fatal(err)
			}

			for _, p := range pkts {
				decryptContext.SetROC(1, p.roc)
				pkt, err := decryptContext.DecryptRTP(nil, p.enc, nil)
				if err != nil {
					t.Errorf("roc=%d, seq=%d: %v", p.roc, p.pkt.SequenceNumber, err)
					continue
				}
				assert.Equal(p.raw, pkt)
			}
		})
	}
}
