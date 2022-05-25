package srtp

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/transport/packetio"
	"github.com/stretchr/testify/assert"
)

type noopConn struct{ closed chan struct{} }

func newNoopConn() *noopConn                           { return &noopConn{closed: make(chan struct{})} }
func (c *noopConn) Read(b []byte) (n int, err error)   { <-c.closed; return 0, io.EOF }
func (c *noopConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *noopConn) Close() error                       { close(c.closed); return nil }
func (c *noopConn) LocalAddr() net.Addr                { return nil }
func (c *noopConn) RemoteAddr() net.Addr               { return nil }
func (c *noopConn) SetDeadline(t time.Time) error      { return nil }
func (c *noopConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *noopConn) SetWriteDeadline(t time.Time) error { return nil }

func TestBufferFactory(t *testing.T) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	conn := newNoopConn()
	bf := func(_ packetio.BufferPacketType, _ uint32) io.ReadWriteCloser {
		wg.Done()
		return packetio.NewBuffer()
	}
	rtpSession, err := NewSessionSRTP(conn, &Config{
		Keys: SessionKeys{
			LocalMasterKey:   make([]byte, 16),
			LocalMasterSalt:  make([]byte, 14),
			RemoteMasterKey:  make([]byte, 16),
			RemoteMasterSalt: make([]byte, 14),
		},
		BufferFactory: bf,
		Profile:       ProtectionProfileAes128CmHmacSha1_80,
	})
	assert.NoError(t, err)
	rtcpSession, err := NewSessionSRTCP(conn, &Config{
		Keys: SessionKeys{
			LocalMasterKey:   make([]byte, 16),
			LocalMasterSalt:  make([]byte, 14),
			RemoteMasterKey:  make([]byte, 16),
			RemoteMasterSalt: make([]byte, 14),
		},
		BufferFactory: bf,
		Profile:       ProtectionProfileAes128CmHmacSha1_80,
	})
	assert.NoError(t, err)

	_, _ = rtpSession.OpenReadStream(123)
	_, _ = rtcpSession.OpenReadStream(123)

	wg.Wait()
}

func benchmarkWrite(b *testing.B, profile ProtectionProfile, size int) {
	conn := newNoopConn()

	keyLen, err := profile.keyLen()
	if err != nil {
		b.Fatal(err)
	}
	saltLen, err := profile.saltLen()
	if err != nil {
		b.Fatal(err)
	}

	config := &Config{
		Keys: SessionKeys{
			LocalMasterKey:   make([]byte, keyLen),
			LocalMasterSalt:  make([]byte, saltLen),
			RemoteMasterKey:  make([]byte, keyLen),
			RemoteMasterSalt: make([]byte, saltLen),
		},
		Profile: profile,
	}

	session, err := NewSessionSRTP(conn, config)
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
		Payload: make([]byte, size),
	}

	packetRaw, err := packet.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(packetRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		packet.Header.SequenceNumber++

		_, err = ws.Write(packetRaw)
		if err != nil {
			b.Fatal(err)
		}
	}

	err = session.Close()
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkWrite(b *testing.B) {
	b.Run("CTR-100", func(b *testing.B) {
		benchmarkWrite(b, profileCTR, 100)
	})
	b.Run("CTR-1000", func(b *testing.B) {
		benchmarkWrite(b, profileCTR, 1000)
	})
	b.Run("GCM-100", func(b *testing.B) {
		benchmarkWrite(b, profileGCM, 100)
	})
	b.Run("GCM-1000", func(b *testing.B) {
		benchmarkWrite(b, profileGCM, 1000)
	})
}

func benchmarkWriteRTP(b *testing.B, profile ProtectionProfile, size int) {
	conn := &noopConn{
		closed: make(chan struct{}),
	}

	keyLen, err := profile.keyLen()
	if err != nil {
		b.Fatal(err)
	}
	saltLen, err := profile.saltLen()
	if err != nil {
		b.Fatal(err)
	}

	config := &Config{
		Keys: SessionKeys{
			LocalMasterKey:   make([]byte, keyLen),
			LocalMasterSalt:  make([]byte, saltLen),
			RemoteMasterKey:  make([]byte, keyLen),
			RemoteMasterSalt: make([]byte, saltLen),
		},
		Profile: profile,
	}

	session, err := NewSessionSRTP(conn, config)
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

	payload := make([]byte, size)

	b.SetBytes(int64(header.MarshalSize() + len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		header.SequenceNumber++

		_, err = ws.WriteRTP(header, payload)
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
	b.Run("CTR-100", func(b *testing.B) {
		benchmarkWriteRTP(b, profileCTR, 100)
	})
	b.Run("CTR-1000", func(b *testing.B) {
		benchmarkWriteRTP(b, profileCTR, 1000)
	})
	b.Run("GCM-100", func(b *testing.B) {
		benchmarkWriteRTP(b, profileGCM, 100)
	})
	b.Run("GCM-1000", func(b *testing.B) {
		benchmarkWriteRTP(b, profileGCM, 1000)
	})
}
