package srtp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/transport/test"
)

func TestSessionSRTPBadInit(t *testing.T) {
	if _, err := NewSessionSRTP(nil, nil); err == nil {
		t.Fatal("NewSessionSRTP should error if no config was provided")
	} else if _, err := NewSessionSRTP(nil, &Config{}); err == nil {
		t.Fatal("NewSessionSRTP should error if no net was provided")
	}
}

func buildSessionSRTPPair(t *testing.T) (*SessionSRTP, *SessionSRTP) {
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
	if err != nil {
		t.Fatal(err)
	} else if aSession == nil {
		t.Fatal("NewSessionSRTP did not error, but returned nil session")
	}

	bSession, err := NewSessionSRTP(bPipe, config)
	if err != nil {
		t.Fatal(err)
	} else if bSession == nil {
		t.Fatal("NewSessionSRTP did not error, but returned nil session")
	}

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
	if err != nil {
		t.Fatal(err)
	}
	if _, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: testSSRC}, append([]byte{}, testPayload...)); err != nil {
		t.Fatal(err)
	}

	bReadStream, ssrc, err := bSession.AcceptStream()
	if err != nil {
		t.Fatal(err)
	} else if ssrc != testSSRC {
		t.Fatalf("SSRC mismatch during accept exp(%v) actual%v)", testSSRC, ssrc)
	}

	if _, err = bReadStream.Read(readBuffer); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testPayload, readBuffer[rtpHeaderSize:]) {
		t.Fatalf("Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer[rtpHeaderSize:])
	}

	if err = aSession.Close(); err != nil {
		t.Fatal(err)
	}

	if err = bSession.Close(); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}

	aWriteStream, err := aSession.OpenWriteStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: testSSRC}, append([]byte{}, testPayload...)); err != nil {
		t.Fatal(err)
	}

	if _, err = bReadStream.Read(readBuffer); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testPayload, readBuffer[rtpHeaderSize:]) {
		t.Fatalf("Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer[rtpHeaderSize:])
	}

	if err = aSession.Close(); err != nil {
		t.Fatal(err)
	}

	if err = bSession.Close(); err != nil {
		t.Fatal(err)
	}
}
