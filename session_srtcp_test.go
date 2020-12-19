package srtp

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/transport/test"
)

const rtcpHeaderSize = 4

func TestSessionSRTCPBadInit(t *testing.T) {
	if _, err := NewSessionSRTCP(nil, nil); err == nil {
		t.Fatal("NewSessionSRTCP should error if no config was provided")
	} else if _, err := NewSessionSRTCP(nil, &Config{}); err == nil {
		t.Fatal("NewSessionSRTCP should error if no net was provided")
	}
}

func buildSessionSRTCP(t *testing.T) (*SessionSRTCP, net.Conn, *Config) {
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
	if err != nil {
		t.Fatal(err)
	} else if aSession == nil {
		t.Fatal("NewSessionSRTCP did not error, but returned nil session")
	}

	return aSession, bPipe, config
}

func buildSessionSRTCPPair(t *testing.T) (*SessionSRTCP, *SessionSRTCP) { //nolint:dupl
	aSession, bPipe, config := buildSessionSRTCP(t)
	bSession, err := NewSessionSRTCP(bPipe, config)
	if err != nil {
		t.Fatal(err)
	} else if bSession == nil {
		t.Fatal("NewSessionSRTCP did not error, but returned nil session")
	}

	return aSession, bSession
}

func TestSessionSRTCP(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	if err != nil {
		t.Fatal(err)
	}
	readBuffer := make([]byte, len(testPayload))
	aSession, bSession := buildSessionSRTCPPair(t)

	aWriteStream, err := aSession.OpenWriteStream()
	if err != nil {
		t.Fatal(err)
	}

	if _, err = aWriteStream.Write(testPayload); err != nil {
		t.Fatal(err)
	}

	bReadStream, _, err := bSession.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}

	if _, err = bReadStream.Read(readBuffer); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testPayload, readBuffer) {
		t.Fatalf("Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)
	}

	if err = aSession.Close(); err != nil {
		t.Fatal(err)
	}

	if err = bSession.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionSRTCPWithIODeadline(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	if err != nil {
		t.Fatal(err)
	}
	readBuffer := make([]byte, len(testPayload))
	aSession, bPipe, config := buildSessionSRTCP(t)

	aWriteStream, err := aSession.OpenWriteStream()
	if err != nil {
		t.Fatal(err)
	}
	// When the other peer is not ready, the Write would be blocked if no deadline.
	if err = aWriteStream.SetWriteDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = aWriteStream.Write(testPayload); !errIsTimeout(err) {
		t.Fatalf("Unexcepted write-error(%v)", err)
	}
	if err = aWriteStream.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Setup another peer.
	bSession, err := NewSessionSRTCP(bPipe, config)
	if err != nil {
		t.Fatal(err)
	} else if bSession == nil {
		t.Fatal("NewSessionSRTCP did not error, but returned nil session")
	}

	// The second attempt to write.
	if _, err = aWriteStream.Write(testPayload); err != nil {
		// The other peer is ready, this write attempt should work.
		t.Fatal(err)
	}

	bReadStream, _, err := bSession.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bReadStream.Read(readBuffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testPayload, readBuffer) {
		t.Fatalf("Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)
	}

	// The second Read attempt would be blocked if the deadline is not set.
	if err = bReadStream.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = bReadStream.Read(readBuffer); !errIsTimeout(err) {
		t.Fatalf("Unexpected read-error(%v)", err)
	}

	if err = aSession.Close(); err != nil {
		t.Fatal(err)
	}
	if err = bSession.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionSRTCPOpenReadStream(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	testPayload, err := rtcp.Marshal([]rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: 5000}})
	if err != nil {
		t.Fatal(err)
	}
	readBuffer := make([]byte, len(testPayload))
	aSession, bSession := buildSessionSRTCPPair(t)

	bReadStream, err := bSession.OpenReadStream(5000)
	if err != nil {
		t.Fatal(err)
	}

	aWriteStream, err := aSession.OpenWriteStream()
	if err != nil {
		t.Fatal(err)
	}

	if _, err = aWriteStream.Write(testPayload); err != nil {
		t.Fatal(err)
	}

	if _, err = bReadStream.Read(readBuffer); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testPayload, readBuffer) {
		t.Fatalf("Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer)
	}

	if err = aSession.Close(); err != nil {
		t.Fatal(err)
	}

	if err = bSession.Close(); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}

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
		if eerr != nil {
			t.Fatal(eerr)
		}
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
			} else if perr == io.EOF {
				return
			}
		}
	}()

	// Write with replay attack
	for _, p := range packets {
		if _, err = aSession.session.nextConn.Write(p); err != nil {
			t.Fatal(err)
		}
		// Immediately replay
		if _, err = aSession.session.nextConn.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range packets {
		// Delayed replay
		if _, err = aSession.session.nextConn.Write(p); err != nil {
			t.Fatal(err)
		}
	}

	if err = aSession.Close(); err != nil {
		t.Fatal(err)
	}
	if err = bSession.Close(); err != nil {
		t.Fatal(err)
	}
	if err = bReadStream.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if !reflect.DeepEqual(expectedSSRC, receivedSSRC) {
		t.Errorf("Expected and received packet differs,\nexpected:\n%v\nreceived:\n%v",
			expectedSSRC, receivedSSRC,
		)
	}
}

func getSenderSSRC(t *testing.T, stream *ReadStreamSRTCP) (ssrc uint32, err error) {
	authTagSize, err := ProtectionProfileAes128CmHmacSha1_80.authTagLen()
	if err != nil {
		return 0, err
	}

	const pliPacketSize = 8
	readBuffer := make([]byte, pliPacketSize+authTagSize+srtcpIndexSize)
	n, _, err := stream.ReadRTCP(readBuffer)
	if err == io.EOF {
		return 0, err
	}
	if err != nil {
		t.Error(err)
		return 0, err
	}
	pli := &rtcp.PictureLossIndication{}
	if uerr := pli.Unmarshal(readBuffer[:n]); uerr != nil {
		t.Error(uerr)
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
