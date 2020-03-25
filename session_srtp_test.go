package srtp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
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
		if err != nil {
			t.Fatal(err)
		}
		bReadStreams[ssrc] = bReadStream
	}

	aWriteStream, err := aSession.OpenWriteStream()
	if err != nil {
		t.Fatal(err)
	}
	for _, ssrc := range ssrcs {
		if _, err = aWriteStream.WriteRTP(&rtp.Header{SSRC: ssrc}, append([]byte{}, testPayload...)); err != nil {
			t.Fatal(err)
		}

		readBuffer := make([]byte, rtpHeaderSize+len(testPayload))
		if _, err = bReadStreams[ssrc].Read(readBuffer); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(testPayload, readBuffer[rtpHeaderSize:]) {
			t.Fatalf("Sent buffer does not match the one received exp(%v) actual(%v)", testPayload, readBuffer[rtpHeaderSize:])
		}
	}

	if err = aSession.Close(); err != nil {
		t.Fatal(err)
	}

	if err = bSession.Close(); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}

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
		if eerr != nil {
			t.Fatal(eerr)
		}
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

	if !reflect.DeepEqual(expectedSequenceNumber, receivedSequenceNumber) {
		t.Errorf("Expected and received sequence number differs,\nexpected:\n%v\nreceived:\n%v",
			expectedSequenceNumber, receivedSequenceNumber,
		)
	}
}

func assertPayloadSRTP(t *testing.T, stream *ReadStreamSRTP, headerSize int, expectedPayload []byte) (seq uint16, err error) {
	readBuffer := make([]byte, headerSize+len(expectedPayload))
	n, hdr, err := stream.ReadRTP(readBuffer)
	if err == io.EOF {
		return 0, err
	}
	if err != nil {
		t.Error(err)
		return 0, err
	}
	if !bytes.Equal(expectedPayload, readBuffer[headerSize:n]) {
		t.Errorf("Sent buffer does not match the one received exp(%v) actual(%v)", expectedPayload, readBuffer[headerSize:n])
		return 0, errors.New("payload differs")
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
