package srtp

import (
	"context"
	"io"
	"testing"

	"github.com/pion/rtp"
)

type noopConn struct{ closed chan struct{} }

func newNoopConn() *noopConn { return &noopConn{closed: make(chan struct{})} }
func (c *noopConn) ReadContext(ctx context.Context, b []byte) (n int, err error) {
	<-c.closed
	return 0, io.EOF
}
func (c *noopConn) WriteContext(ctx context.Context, b []byte) (n int, err error) { return len(b), nil }
func (c *noopConn) Close() error                                                  { close(c.closed); return nil }

func BenchmarkWrite(b *testing.B) {
	ctx := context.Background()
	conn := newNoopConn()

	config := &Config{
		Keys: SessionKeys{
			LocalMasterKey:   make([]byte, 16),
			LocalMasterSalt:  make([]byte, 14),
			RemoteMasterKey:  make([]byte, 16),
			RemoteMasterSalt: make([]byte, 14),
		},
		Profile: ProtectionProfileAes128CmHmacSha1_80,
	}

	session, err := NewSessionSRTP(ctx, conn, config)
	if err != nil {
		b.Fatal(err)
	}

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

	packetRaw, err := packet.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packet.Header.SequenceNumber++

		_, err = ws.WriteContext(ctx, packetRaw)
		if err != nil {
			b.Fatal(err)
		}
	}

	err = session.Close()
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkWriteRTP(b *testing.B) {
	ctx := context.Background()
	conn := &noopConn{
		closed: make(chan struct{}),
	}

	config := &Config{
		Keys: SessionKeys{
			LocalMasterKey:   make([]byte, 16),
			LocalMasterSalt:  make([]byte, 14),
			RemoteMasterKey:  make([]byte, 16),
			RemoteMasterSalt: make([]byte, 14),
		},
		Profile: ProtectionProfileAes128CmHmacSha1_80,
	}

	session, err := NewSessionSRTP(ctx, conn, config)
	if err != nil {
		b.Fatal(err)
	}

	ws, err := session.OpenWriteStream()
	if err != nil {
		b.Fatal(err)
	}

	header := &rtp.Header{
		Version: 2,
		SSRC:    322,
	}

	payload := make([]byte, 100)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		header.SequenceNumber++

		_, err = ws.WriteRTP(ctx, header, payload)
		if err != nil {
			b.Fatal(err)
		}
	}

	err = session.Close()
	if err != nil {
		b.Fatal(err)
	}
}
