package srtp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/transport/test"
)

func TestSessionSRTCPBadInit(t *testing.T) {
	if _, err := NewSessionSRTCP(nil, nil); err == nil {
		t.Fatal("NewSessionSRTCP should error if no config was provided")
	} else if _, err := NewSessionSRTCP(nil, &Config{}); err == nil {
		t.Fatal("NewSessionSRTCP should error if no net was provided")
	}
}

func buildSessionSRTCPPair(t *testing.T) (*SessionSRTCP, *SessionSRTCP) {
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
