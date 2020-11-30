package srtp

import (
	"context"
	"errors"
	"sync"

	"github.com/pion/rtcp"
	"github.com/pion/transport/packetio"
)

// Limit the buffer size to 100KB
const srtcpBufferSize = 100 * 1000

// ReadStreamSRTCP handles decryption for a single RTCP SSRC
type ReadStreamSRTCP struct {
	mu sync.Mutex

	isInited bool
	isClosed chan bool

	session *SessionSRTCP
	ssrc    uint32

	buffer *packetio.Buffer
}

func (r *ReadStreamSRTCP) write(ctx context.Context, buf []byte) (n int, err error) {
	n, err = r.buffer.WriteContext(ctx, buf)

	if errors.Is(err, packetio.ErrFull) {
		// Silently drop data when the buffer is full.
		return len(buf), nil
	}

	return n, err
}

// Used by getOrCreateReadStream
func newReadStreamSRTCP() readStream {
	return &ReadStreamSRTCP{}
}

// ReadRTCP reads and decrypts full RTCP packet and its header from the nextConn
func (r *ReadStreamSRTCP) ReadRTCP(ctx context.Context, buf []byte) (int, *rtcp.Header, error) {
	n, err := r.ReadContext(ctx, buf)
	if err != nil {
		return 0, nil, err
	}

	header := &rtcp.Header{}
	err = header.Unmarshal(buf[:n])
	if err != nil {
		return 0, nil, err
	}

	return n, header, nil
}

// ReadContext reads and decrypts full RTCP packet from the nextConn
func (r *ReadStreamSRTCP) ReadContext(ctx context.Context, buf []byte) (int, error) {
	return r.buffer.ReadContext(ctx, buf)
}

// Close removes the ReadStream from the session and cleans up any associated state
func (r *ReadStreamSRTCP) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isInited {
		return errStreamNotInited
	}

	select {
	case <-r.isClosed:
		return errStreamAlreadyClosed
	default:
		err := r.buffer.Close()
		if err != nil {
			return err
		}

		r.session.removeReadStream(r.ssrc)
		return nil
	}
}

func (r *ReadStreamSRTCP) init(child streamSession, ssrc uint32) error {
	sessionSRTCP, ok := child.(*SessionSRTCP)

	r.mu.Lock()
	defer r.mu.Unlock()
	if !ok {
		return errFailedTypeAssertion
	} else if r.isInited {
		return errStreamAlreadyInited
	}

	r.session = sessionSRTCP
	r.ssrc = ssrc
	r.isInited = true
	r.isClosed = make(chan bool)

	// Create a buffer and limit it to 100KB
	r.buffer = packetio.NewBuffer()
	r.buffer.SetLimitSize(srtcpBufferSize)

	return nil
}

// GetSSRC returns the SSRC we are demuxing for
func (r *ReadStreamSRTCP) GetSSRC() uint32 {
	return r.ssrc
}

// WriteStreamSRTCP is stream for a single Session that is used to encrypt RTCP
type WriteStreamSRTCP struct {
	session *SessionSRTCP
}

// WriteRTCP encrypts a RTCP header and its payload to the nextConn
func (w *WriteStreamSRTCP) WriteRTCP(ctx context.Context, header *rtcp.Header, payload []byte) (int, error) {
	headerRaw, err := header.Marshal()
	if err != nil {
		return 0, err
	}

	return w.session.write(ctx, append(headerRaw, payload...))
}

// WriteContext encrypts and writes a full RTCP packets to the nextConn
func (w *WriteStreamSRTCP) WriteContext(ctx context.Context, b []byte) (int, error) {
	return w.session.write(ctx, b)
}
