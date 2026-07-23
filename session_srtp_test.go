// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
)

func TestSessionSRTPBadInit(t *testing.T) {
	_, err := NewSessionSRTP(nil, nil)
	assert.Error(t, err, "NewSessionSRTP should error if no net was provided")

	_, err = NewSessionSRTP(nil, &Config{})
	assert.Error(t, err, "NewSessionSRTP should error if no net was provided")
}

func buildSessionSRTP(t *testing.T) (*SessionSRTP, net.Conn, *Config) { //nolint:dupl
	t.Helper()

	aPipe, bPipe := net.Pipe()
	config := &Config{
		Profile: ProtectionProfileAes128CmHmacSha1_80,
		Keys: SessionKeys{
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
		},
	}

	aSession, err := NewSessionSRTP(aPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, aSession, "NewSessionSRTP did not error, but returned nil session")

	return aSession, bPipe, config
}

func buildSessionSRTPPair(t *testing.T) (*SessionSRTP, *SessionSRTP) { //nolint:dupl
	t.Helper()

	aSession, bPipe, config := buildSessionSRTP(t)
	bSession, err := NewSessionSRTP(bPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, bSession, "NewSessionSRTP did not error, but returned nil session")

	return aSession, bSession
}

func TestSessionSRTP(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC      = 5000
		rtpHeaderSize = 12
	)
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}
	readBuffer := make([]byte, rtpHeaderSize+len(testPayload))
	aSession, bSession := buildSessionSRTPPair(t)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	_, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: testSSRC}, append([]byte{}, testPayload...))
	assert.NoError(t, err)

	bReadStream, ssrc, err := bSession.AcceptStream()
	assert.NoError(t, err)
	assert.Equalf(t, uint32(testSSRC), ssrc, "SSRC mismatch during accept exp(%v) actual(%v)", testSSRC, ssrc)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, readBuffer[rtpHeaderSize:], testPayload,
		"Sent buffer does not match the one received exp(%v) actual(%v)",
		testPayload, readBuffer[rtpHeaderSize:])

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTPWithIODeadline(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC      = 5000
		rtpHeaderSize = 12
	)
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}
	readBuffer := make([]byte, rtpHeaderSize+len(testPayload))
	aSession, bPipe, config := buildSessionSRTP(t)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	// When the other peer is not ready, the Write would be blocked if no deadline.
	assert.NoError(t, aWriteStream.SetWriteDeadline(time.Now().Add(1*time.Second)))

	_, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: testSSRC}, append([]byte{}, testPayload...))
	assert.Truef(t, errIsTimeout(err), "Unexpected read-error(%v)", err)
	assert.NoError(t, aWriteStream.SetWriteDeadline(time.Time{}))

	// Setup another peer.
	bSession, err := NewSessionSRTP(bPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, bSession, "NewSessionSRTP did not error, but returned nil session")

	// The second attempt to write, even without deadline.
	_, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: testSSRC}, append([]byte{}, testPayload...))
	assert.NoError(t, err)

	bReadStream, ssrc, err := bSession.AcceptStream()
	assert.NoError(t, err)
	assert.Equal(t, uint32(testSSRC), ssrc, "SSRC mismatch during accept exp(%v) actual(%v)", testSSRC, ssrc)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equal(t, testPayload, readBuffer[rtpHeaderSize:],
		"Sent buffer does not match the one received exp(%v) actual(%v)",
		testPayload, readBuffer[rtpHeaderSize:])

	// The second Read attempt would be blocked if the deadline is not set.
	assert.NoError(t, bReadStream.SetReadDeadline(time.Now().Add(1*time.Second)))

	_, err = bReadStream.Read(readBuffer)
	assert.Truef(t, errIsTimeout(err), "Unexpected read-error(%v)", err)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTPOpenReadStream(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC      = 5000
		rtpHeaderSize = 12
	)
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}
	readBuffer := make([]byte, rtpHeaderSize+len(testPayload))
	aSession, bSession := buildSessionSRTPPair(t)

	bReadStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	_, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: testSSRC}, append([]byte{}, testPayload...))
	assert.NoError(t, err)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, testPayload, readBuffer[rtpHeaderSize:],
		"Sent buffer does not match the one received exp(%v) actual(%v)",
		testPayload, readBuffer[rtpHeaderSize:])

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTPMultiSSRC(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const rtpHeaderSize = 12
	ssrcs := []uint32{5000, 5001, 5002}
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}
	aSession, bSession := buildSessionSRTPPair(t)

	bReadStreams := make(map[uint32]*ReadStreamSRTP)
	for _, ssrc := range ssrcs {
		bReadStream, err := bSession.OpenReadStream(ssrc)
		assert.NoError(t, err)

		bReadStreams[ssrc] = bReadStream
	}

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	for _, ssrc := range ssrcs {
		_, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: ssrc}, append([]byte{}, testPayload...))
		assert.NoError(t, err)

		readBuffer := make([]byte, rtpHeaderSize+len(testPayload))
		_, err = bReadStreams[ssrc].Read(readBuffer)
		assert.NoError(t, err)

		assert.Equal(t, testPayload, readBuffer[rtpHeaderSize:],
			"Sent buffer does not match the one received exp(%v) actual(%v)",
			testPayload, readBuffer[rtpHeaderSize:])
	}

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTPReplayProtection(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC      = 5000
		rtpHeaderSize = 12
	)
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}
	aSession, bSession := buildSessionSRTPPair(t)
	bReadStream, err := bSession.OpenReadStream(testSSRC)
	assert.NoError(t, err)

	// Generate test packets
	var packets [][]byte
	var expectedSequenceNumber []uint16
	for i := uint16(0xFF00); i != 0x100; i++ {
		expectedSequenceNumber = append(expectedSequenceNumber, i)
		encrypted, eerr := encryptSRTP(aSession.session.localContext, &rtp.Packet{
			Header: rtp.Header{
				SSRC:           testSSRC,
				SequenceNumber: i,
			},
			Payload: testPayload,
		})
		assert.NoError(t, eerr)
		packets = append(packets, encrypted)
	}

	// Receive SRTP packets with replay protection
	var receivedSequenceNumber []uint16
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if seq, perr := assertPayloadSRTP(t, bReadStream, rtpHeaderSize, testPayload); perr == nil {
				receivedSequenceNumber = append(receivedSequenceNumber, seq)
			} else if errors.Is(perr, io.EOF) {
				return
			}
		}
	}()

	// Write with replay attack
	for _, p := range packets {
		_, err = aSession.session.nextConn.Write(p)
		assert.NoError(t, err)
		// Immediately replay
		_, err = aSession.session.nextConn.Write(p)
		assert.NoError(t, err)
	}
	for _, p := range packets {
		// Delayed replay
		_, err = aSession.session.nextConn.Write(p)
		assert.NoError(t, err)
	}

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
	assert.NoError(t, bReadStream.Close())

	wg.Wait()

	assert.Equalf(t, expectedSequenceNumber, receivedSequenceNumber,
		"Expected and received sequence number differs,\nexpected:\n%v\nreceived:\n%v",
		expectedSequenceNumber, receivedSequenceNumber)
}

// nolint: dupl
func TestSessionSRTPAcceptStreamTimeout(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	pipe, _ := net.Pipe()
	config := &Config{
		Profile: ProtectionProfileAes128CmHmacSha1_80,
		Keys: SessionKeys{
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6},
		},
		AcceptStreamTimeout: time.Now().Add(3 * time.Second),
	}

	newSession, err := NewSessionSRTP(pipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, newSession, "NewSessionSRTP did not error, but returned nil session")

	_, _, err = newSession.AcceptStream()
	assert.ErrorIs(t, err, errStreamAlreadyClosed)

	assert.NoError(t, newSession.Close())
}

func assertPayloadSRTP(
	t *testing.T,
	stream *ReadStreamSRTP,
	headerSize int,
	expectedPayload []byte,
) (seq uint16, err error) {
	t.Helper()

	readBuffer := make([]byte, headerSize+len(expectedPayload))
	n, hdr, err := stream.ReadRTP(readBuffer)
	if errors.Is(err, io.EOF) {
		return 0, err
	}
	if !assert.NoError(t, err) {
		return 0, err
	}
	if !assert.Equalf(t, expectedPayload, readBuffer[headerSize:n],
		"Sent buffer does not match the one received exp(%v) actual(%v)",
		expectedPayload, readBuffer[headerSize:n]) {
		return 0, errPayloadDiffers
	}

	return hdr.SequenceNumber, nil
}

func TestSessionSRTPFailedAuthDoesNotGrowStreams(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		badSSRC  = uint32(0xDEADBEEF)
		goodSSRC = uint32(0x12345678)
	)

	aSession, bSession := buildSessionSRTPPair(t)

	// Encrypt a packet for badSSRC with the correct key, then corrupt its auth tag
	// so that bSession's remote context rejects it without creating a stream entry.
	badPkt := &rtp.Packet{
		Payload: []byte{0x00, 0x01, 0x02, 0x03},
		Header:  rtp.Header{SSRC: badSSRC, SequenceNumber: 1},
	}
	badEncrypted, err := encryptSRTP(aSession.session.localContext, badPkt)
	assert.NoError(t, err)
	badEncrypted[len(badEncrypted)-1] ^= 0xFF // corrupt last byte of auth tag

	_, err = aSession.session.nextConn.Write(badEncrypted)
	assert.NoError(t, err)

	// Write a valid packet for goodSSRC so we can synchronize via AcceptStream.
	// The read goroutine processes packets sequentially, so when AcceptStream
	// returns the bad packet has already been handled.
	goodPkt := &rtp.Packet{
		Payload: []byte{0x00, 0x01, 0x02, 0x03},
		Header:  rtp.Header{SSRC: goodSSRC, SequenceNumber: 1},
	}
	goodEncrypted, err := encryptSRTP(aSession.session.localContext, goodPkt)
	assert.NoError(t, err)

	_, err = aSession.session.nextConn.Write(goodEncrypted)
	assert.NoError(t, err)

	_, receivedSSRC, err := bSession.AcceptStream()
	assert.NoError(t, err)
	assert.Equal(t, goodSSRC, receivedSSRC, "AcceptStream must return the valid SSRC")

	bSession.session.readStreamsLock.Lock()
	streamCount := len(bSession.session.readStreams)
	_, hasBadSSRC := bSession.session.readStreams[badSSRC]
	bSession.session.readStreamsLock.Unlock()

	assert.Equal(t, 1, streamCount, "readStreams must not grow after failed authentication")
	assert.False(t, hasBadSSRC, "readStreams must not contain the SSRC from the rejected packet")

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func encryptSRTP(context *Context, pkt *rtp.Packet) ([]byte, error) {
	decryptedRaw, err := pkt.Marshal()
	if err != nil {
		return nil, err
	}
	encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+10)
	copy(encryptInput, decryptedRaw)
	encrypted, eerr := context.EncryptRTP(encryptInput, encryptInput, nil)
	if eerr != nil {
		return nil, eerr
	}

	return encrypted, nil
}

func TestSessionSRTPPacketWithPadding(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC      = 5000
		rtpHeaderSize = 12
		paddingSize   = 5
		authTagLen    = 10 // For AES_CM_128_HMAC_SHA1_80, the auth tag length is 10 bytes.
	)
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}
	readBuffer := make([]byte, rtpHeaderSize+paddingSize+len(testPayload))
	aSession, bSession := buildSessionSRTPPair(t)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	writeBytes, err := aWriteStream.WriteRTP(&rtp.Header{SSRC: testSSRC, Padding: true, PaddingSize: paddingSize},
		append([]byte{}, testPayload...))
	assert.NoError(t, err)
	assert.Equalf(t, rtpHeaderSize+paddingSize+len(testPayload)+authTagLen, writeBytes,
		"WriteRTP should return the size of the packet including padding, exp(%v) actual(%v)",
		rtpHeaderSize+paddingSize+len(testPayload)+authTagLen, writeBytes)

	bReadStream, ssrc, err := bSession.AcceptStream()
	assert.NoError(t, err)
	assert.Equalf(t, uint32(testSSRC), ssrc, "SSRC mismatch during accept exp(%v) actual(%v)", testSSRC, ssrc)

	readBytes, err := bReadStream.Read(readBuffer)
	assert.NoError(t, err)
	assert.Equal(t, rtpHeaderSize+paddingSize+len(testPayload), readBytes,
		"Read should return the size of the packet including padding, exp(%v) actual(%v)",
		rtpHeaderSize+paddingSize+len(testPayload), readBytes)

	var rtpPacket rtp.Packet
	err = rtpPacket.Unmarshal(readBuffer[:readBytes])
	assert.NoError(t, err)
	assert.Equal(t, rtpPacket.Padding, true)
	assert.Equal(t, rtpPacket.PaddingSize, byte(paddingSize))
	assert.Equal(t, rtpPacket.Payload, testPayload)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTPRejectedPacketDoesNotGrowRetainedHeader(t *testing.T) {
	const (
		packetSize             = 8192
		rtpFixedHeaderSize     = 12
		rtpExtensionHeaderSize = 4
		initialCapacity        = 1
	)

	assertDoesNotGrow := func(t *testing.T, receiver *SessionSRTP, packet []byte) {
		t.Helper()

		receiver.readHeader.CSRC = make([]uint32, 0, initialCapacity)
		receiver.readHeader.Extensions = make([]rtp.Extension, 0, initialCapacity)

		assert.Error(t, receiver.decrypt(packet))
		assert.Equal(t, initialCapacity, cap(receiver.readHeader.CSRC))
		assert.Equal(t, initialCapacity, cap(receiver.readHeader.Extensions))
	}

	t.Run("invalid CSRC header", func(t *testing.T) {
		// CC=15 causes Header.Unmarshal to grow the CSRC slice before
		// discovering that the packet is too short.
		packet := make([]byte, rtpFixedHeaderSize)
		packet[0] = 2<<6 | 15

		assertDoesNotGrow(t, &SessionSRTP{}, packet)
	})

	t.Run("invalid extension header", func(t *testing.T) {
		packet := make([]byte, packetSize)
		packet[0] = 2<<6 | 1<<4 // Version 2, extension bit set.

		extensionOffset := rtpFixedHeaderSize
		binary.BigEndian.PutUint16(
			packet[extensionOffset:],
			rtp.ExtensionProfileTwoByte,
		)

		extensionData := packet[extensionOffset+rtpExtensionHeaderSize:]
		binary.BigEndian.PutUint16(
			packet[extensionOffset+2:],
			uint16(len(extensionData)/4), //nolint:gosec
		)

		// Add thousands of valid zero-length extensions, followed by one byte
		// of padding and an extension ID without its required length byte.
		// Unmarshal therefore grows Extensions substantially before failing.
		for i := 0; i < len(extensionData)-2; i += 2 {
			extensionData[i] = 1
		}
		extensionData[len(extensionData)-1] = 1

		assertDoesNotGrow(t, &SessionSRTP{}, packet)
	})

	t.Run("authentication failure", func(t *testing.T) {
		const (
			authTagSize = 16
			csrcCount   = 15
			testSSRC    = 5000
		)

		key := make([]byte, 16)
		salt := make([]byte, 12)

		encryptContext, err := CreateContext(
			key,
			salt,
			ProtectionProfileAeadAes128Gcm,
		)
		if !assert.NoError(t, err) {
			return
		}

		decryptContext, err := CreateContext(
			key,
			salt,
			ProtectionProfileAeadAes128Gcm,
		)
		if !assert.NoError(t, err) {
			return
		}

		plaintext := make([]byte, packetSize-authTagSize)
		plaintext[0] = 2<<6 | 1<<4 | csrcCount
		binary.BigEndian.PutUint32(plaintext[8:], testSSRC)

		extensionOffset := rtpFixedHeaderSize + (csrcCount * 4)
		binary.BigEndian.PutUint16(
			plaintext[extensionOffset:],
			rtp.ExtensionProfileTwoByte,
		)

		extensionData := plaintext[extensionOffset+rtpExtensionHeaderSize:]
		binary.BigEndian.PutUint16(
			plaintext[extensionOffset+2:],
			uint16(len(extensionData)/4), //nolint:gosec
		)

		// Each two-byte extension consists of an ID and a zero payload length.
		for i := 0; i < len(extensionData); i += 2 {
			extensionData[i] = 1
		}

		encrypted, err := encryptContext.EncryptRTP(nil, plaintext, nil)
		if !assert.NoError(t, err) {
			return
		}

		// Ensure authentication fails after the header slices have been grown.
		encrypted[len(encrypted)-1] ^= 0xFF

		receiver := &SessionSRTP{
			session: session{remoteContext: decryptContext},
		}
		assertDoesNotGrow(t, receiver, encrypted)
	})
}

func TestSessionSRTPReadWriteDoesNotAllocate(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const testSSRC = 5000
	testPayload := []byte{0x00, 0x01, 0x03, 0x04}
	readBuffer := make([]byte, 1500)

	// Note: this does not use buildSessionSRTPPair for two reasons:
	// - The CTR cipher uses a sync.Pool, which under the race detector
	//   always allocates.
	// - The default replay detector (as of pion/transport 4.0.2) allocates
	//
	// In order to isolate allocations to this package and avoid race
	// detector related allocations, test the GCM cipher using a no-op
	// replay detector instead.
	aPipe, bPipe := net.Pipe()
	noReplayProtection := []ContextOption{
		SRTPNoReplayProtection(),
		SRTCPNoReplayProtection(),
	}
	config := &Config{
		Profile: ProtectionProfileAeadAes128Gcm,
		Keys: SessionKeys{
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A},
			[]byte{0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39},
			[]byte{0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A},
		},
		LocalOptions:  noReplayProtection,
		RemoteOptions: noReplayProtection,
	}

	aSession, err := NewSessionSRTP(aPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, aSession, "NewSessionSRTP did not error, but returned nil session")

	bSession, err := NewSessionSRTP(bPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, bSession, "NewSessionSRTP did not error, but returned nil session")

	bReadStream, err := bSession.OpenReadStream(testSSRC)
	assert.NoError(t, err)
	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	header := &rtp.Header{
		Version:          2,
		SSRC:             testSSRC,
		Extension:        true,
		ExtensionProfile: rtp.ExtensionProfileOneByte,
	}
	assert.NoError(t, header.SetExtension(1, []byte{0xAA, 0xBB}))

	roundTrip := func() (int, error) {
		header.SequenceNumber++
		if _, err := aWriteStream.WriteRTP(header, testPayload); err != nil {
			return 0, err
		}

		return bReadStream.Read(readBuffer)
	}

	for range 100 {
		_, err := roundTrip()
		assert.NoError(t, err)
	}

	var roundTripErr error
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := roundTrip(); err != nil {
			roundTripErr = err
		}
	})

	assert.NoError(t, roundTripErr)
	assert.Zero(t, allocs)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func BenchmarkSessionSRTPReadWrite(b *testing.B) {
	for _, profile := range []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileNullHmacSha1_80,
		ProtectionProfileNullHmacSha1_32,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	} {
		b.Run(profile.String(), func(b *testing.B) {
			keyLen, err := profile.KeyLen()
			assert.NoError(b, err)
			saltLen, err := profile.SaltLen()
			assert.NoError(b, err)
			key := make([]byte, keyLen)
			salt := make([]byte, saltLen)
			for i := range key {
				key[i] = byte(i + 1)
			}
			for i := range salt {
				salt[i] = byte(i + 101)
			}

			// See TestSessionSRTPReadWriteDoesNotAllocate for why this
			// doesn't use buildSessionSRTPPair.
			aPipe, bPipe := net.Pipe()
			noReplayProtection := []ContextOption{
				SRTPNoReplayProtection(),
				SRTCPNoReplayProtection(),
			}
			loggerFactory := logging.NewDefaultLoggerFactory()
			loggerFactory.DefaultLogLevel.Set(logging.LogLevelDisabled)
			config := &Config{
				LoggerFactory: loggerFactory,
				Profile:       profile,
				Keys: SessionKeys{
					LocalMasterKey:   key,
					LocalMasterSalt:  salt,
					RemoteMasterKey:  key,
					RemoteMasterSalt: salt,
				},
				LocalOptions:  noReplayProtection,
				RemoteOptions: noReplayProtection,
			}

			aSession, err := NewSessionSRTP(aPipe, config)
			assert.NoError(b, err)
			bSession, err := NewSessionSRTP(bPipe, config)
			assert.NoError(b, err)
			defer func() {
				assert.NoError(b, aSession.Close())
				assert.NoError(b, bSession.Close())
			}()

			bReadStream, err := bSession.OpenReadStream(5000)
			assert.NoError(b, err)
			aWriteStream, err := aSession.OpenWriteStream()
			assert.NoError(b, err)

			header := &rtp.Header{
				Version:          2,
				SSRC:             5000,
				Extension:        true,
				ExtensionProfile: rtp.ExtensionProfileOneByte,
			}
			assert.NoError(b, header.SetExtension(1, []byte{0xAA, 0xBB}))
			testPayload := []byte{0x00, 0x01, 0x03, 0x04}
			readBuffer := make([]byte, 1500)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				header.SequenceNumber++
				if _, err := aWriteStream.WriteRTP(header, testPayload); err != nil {
					b.Fatal(err)
				}
				if _, err := bReadStream.Read(readBuffer); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
