package srtp

import (
	"net"
	"testing"

	"github.com/pions/rtp"
)

func checkError(b *testing.B, f func() error) {
	err := f()
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkWriteRTP(b *testing.B) {
	conn1, conn2 := net.Pipe()
	defer checkError(b, conn1.Close)
	defer checkError(b, conn2.Close)

	go func() {
		buffer := [512]byte{}

		for {
			_, err := conn2.Read(buffer[:])
			if err != nil {
				break
			}
		}
	}()

	config := &Config{
		Keys: SessionKeys{
			LocalMasterKey:   make([]byte, 16),
			LocalMasterSalt:  make([]byte, 14),
			RemoteMasterKey:  make([]byte, 16),
			RemoteMasterSalt: make([]byte, 14),
		},
		Profile: ProtectionProfileAes128CmHmacSha1_80,
	}

	session, err := NewSessionSRTP(conn1, config)
	if err != nil {
		b.Fatal(err)
	}

	defer checkError(b, session.Close)

	ws, err := session.OpenWriteStream()
	if err != nil {
		b.Fatal(err)
	}

	packet := &rtp.Packet{
		Header: rtp.Header{
			Version: 2,
			SSRC:    322,
		},
		Payload: make([]byte, 100),
	}

	for i := 0; i < b.N; i++ {
		packet.Header.SequenceNumber++

		err = ws.WriteRTP(packet)
		if err != nil {
			b.Fatal(err)
		}
	}
}
