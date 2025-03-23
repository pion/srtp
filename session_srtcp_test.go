// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/transport/v3/test"
	"github.com/stretchr/testify/assert"
)

const rtcpHeaderSize = 4

func TestSessionSRTCPBadInit(t *testing.T) {
	_, err := NewSessionSRTCP(nil, nil)
	assert.Error(t, err, "NewSessionSRTCP should error if no config was provided")

	_, err = NewSessionSRTCP(nil, &Config{})
	assert.Error(t, err, "NewSessionSRTCP should error if no net was provided")
}

func buildSessionSRTCP(t *testing.T) (*SessionSRTCP, net.Conn, *Config) { //nolint:dupl
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

	aSession, err := NewSessionSRTCP(aPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, aSession, "NewSessionSRTCP did not error, but returned nil session")

	return aSession, bPipe, config
}

func buildSessionSRTCPPair(t *testing.T) (*SessionSRTCP, *SessionSRTCP) { //nolint:dupl
	t.Helper()

	aSession, bPipe, config := buildSessionSRTCP(t)
	bSession, err := NewSessionSRTCP(bPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, bSession, "NewSessionSRTCP did not error, but returned nil session")

	return aSession, bSession
}

func TestSessionSRTCP(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	assert.NoError(t, err)

	readBuffer := make([]byte, len(testPayload))
	aSession, bSession := buildSessionSRTCPPair(t)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	_, err = aWriteStream.Write(testPayload)
	assert.NoError(t, err)

	bReadStream, _, err := bSession.AcceptStream()
	assert.NoError(t, err)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, readBuffer, testPayload,
		"Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPWithIODeadline(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	assert.NoError(t, err)

	readBuffer := make([]byte, len(testPayload))
	aSession, bPipe, config := buildSessionSRTCP(t)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	// When the other peer is not ready, the Write would be blocked if no deadline.
	assert.NoError(t, aWriteStream.SetWriteDeadline(time.Now().Add(1*time.Second)))

	_, err = aWriteStream.Write(testPayload)
	assert.Truef(t, errIsTimeout(err), "Unexpected read-error(%v)", err)

	assert.NoError(t, aWriteStream.SetWriteDeadline(time.Time{}))

	// Setup another peer.
	bSession, err := NewSessionSRTCP(bPipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, bSession, "NewSessionSRTCP did not error, but returned nil session")

	// The second attempt to write.
	_, err = aWriteStream.Write(testPayload)
	// The other peer is ready, this write attempt should work.
	assert.NoError(t, err)

	bReadStream, _, err := bSession.AcceptStream()
	assert.NoError(t, err)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, readBuffer, testPayload,
		"Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)

	// The second Read attempt would be blocked if the deadline is not set.
	assert.NoError(t, bReadStream.SetReadDeadline(time.Now().Add(1*time.Second)))

	_, err = bReadStream.Read(readBuffer)
	assert.Truef(t, errIsTimeout(err), "Unexpected read-error(%v)", err)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPOpenReadStream(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	assert.NoError(t, err)

	readBuffer := make([]byte, len(testPayload))
	aSession, bSession := buildSessionSRTCPPair(t)

	bReadStream, err := bSession.OpenReadStream(5000)
	assert.NoError(t, err)

	aWriteStream, err := aSession.OpenWriteStream()
	assert.NoError(t, err)

	_, err = aWriteStream.Write(testPayload)
	assert.NoError(t, err)

	_, err = bReadStream.Read(readBuffer)
	assert.NoError(t, err)

	assert.Equalf(t, readBuffer, testPayload,
		"Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)

	assert.NoError(t, aSession.Close())
	assert.NoError(t, bSession.Close())
}

func TestSessionSRTCPReplayProtection(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	const (
		testSSRC = 5000
	)
	aSession, bSession := buildSessionSRTCPPair(t)
	bReadStream, err := bSession.OpenReadStream(testSSRC)
	assert.NoError(t, err)

	// Generate test packets
	var packets [][]byte
	var expectedSSRC []uint32
	for i := uint32(0); i < 0x100; i++ {
		testPacket := &rtcp.PictureLossIndication{
			MediaSSRC:  testSSRC,
			SenderSSRC: i,
		}
		expectedSSRC = append(expectedSSRC, i)
		encrypted, eerr := encryptSRTCP(aSession.session.localContext, testPacket)
		assert.NoError(t, eerr)

		packets = append(packets, encrypted)
	}

	// Receive SRTCP packets with replay protection
	var receivedSSRC []uint32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if ssrc, perr := getSenderSSRC(t, bReadStream); perr == nil {
				receivedSSRC = append(receivedSSRC, ssrc)
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

	assert.Equalf(t, expectedSSRC, receivedSSRC,
		"Expected and received SSRCs differ,\nexpected:\n%v\nreceived:\n%v",
		expectedSSRC, receivedSSRC)
}

// nolint: dupl
func TestSessionSRTCPAcceptStreamTimeout(t *testing.T) {
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

	newSession, err := NewSessionSRTCP(pipe, config)
	assert.NoError(t, err)
	assert.NotNil(t, newSession, "NewSessionSRTCP did not error, but returned nil session")

	_, _, err = newSession.AcceptStream()
	if !errors.Is(err, errStreamAlreadyClosed) {
		assert.NoError(t, err)
	}

	assert.NoError(t, newSession.Close())
}

func getSenderSSRC(t *testing.T, stream *ReadStreamSRTCP) (ssrc uint32, err error) {
	t.Helper()

	authTagSize, err := ProtectionProfileAes128CmHmacSha1_80.AuthTagRTCPLen()
	if err != nil {
		return 0, err
	}

	const pliPacketSize = 8
	readBuffer := make([]byte, pliPacketSize+authTagSize+srtcpIndexSize)
	n, _, err := stream.ReadRTCP(readBuffer)
	if errors.Is(err, io.EOF) {
		return 0, err
	}
	if err != nil {
		assert.NoError(t, err)

		return 0, err
	}
	pli := &rtcp.PictureLossIndication{}
	if uerr := pli.Unmarshal(readBuffer[:n]); uerr != nil {
		assert.NoError(t, uerr)

		return 0, uerr
	}

	return pli.SenderSSRC, nil
}

func encryptSRTCP(context *Context, pkt rtcp.Packet) ([]byte, error) {
	decryptedRaw, err := pkt.Marshal()
	if err != nil {
		return nil, err
	}
	encryptInput := make([]byte, len(decryptedRaw), rtcpHeaderSize+len(decryptedRaw)+10)
	copy(encryptInput, decryptedRaw)
	encrypted, eerr := context.EncryptRTCP(encryptInput, encryptInput, nil)
	if eerr != nil {
		return nil, eerr
	}

	return encrypted, nil
}

func errIsTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"): // error message when timeout before go1.15.
		return true
	case strings.Contains(s, "deadline exceeded"): // error message when timeout after go1.15.
		return true
	}

	return false
}
