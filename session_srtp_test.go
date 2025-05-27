// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/transport/v3/test"
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
