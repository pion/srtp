package srtp

import (
	"fmt"
	"sync"

	"github.com/pions/rtcp"
)

type readResultSRTCP struct {
	len    int
	header *rtcp.Header
}

// ReadStreamSRTCP handles decryption for a single RTCP SSRC
type ReadStreamSRTCP struct {
	mu sync.Mutex

	isInited bool
	isClosed chan bool

	session   *SessionSRTCP
	ssrc      uint32
	readCh    chan []byte
	readRetCh chan readResultSRTCP
}

// Used by getOrCreateReadStream
func newReadStreamSRTCP() readStream {
	return &ReadStreamSRTCP{}
}

// ReadRTCP reads and decrypts full RTCP packet and its header from the nextConn
func (r *ReadStreamSRTCP) ReadRTCP(payload []byte) (int, *rtcp.Header, error) {
	select {
	case <-r.session.closed:
		return 0, nil, fmt.Errorf("SRTCP session is closed")
	case r.readCh <- payload:
	case <-r.isClosed:
		return 0, nil, fmt.Errorf("SRTCP read stream is closed")
	}

	select {
	case <-r.session.closed:
		return 0, nil, fmt.Errorf("SRTCP session is closed")
	case res, ok := <-r.readRetCh:
		if !ok {
			return 0, nil, fmt.Errorf("SRTCP read stream is closed")
		}

		return res.len, res.header, nil
	}
}

// Read reads and decrypts full RTCP packet from the nextConn
func (r *ReadStreamSRTCP) Read(b []byte) (int, error) {
	select {
	case <-r.session.closed:
		return 0, fmt.Errorf("SRTCP session is closed")
	case r.readCh <- b:
	case <-r.isClosed:
		return 0, fmt.Errorf("SRTCP read stream is closed")
	}

	select {
	case <-r.session.closed:
		return 0, fmt.Errorf("SRTCP session is closed")
	case res, ok := <-r.readRetCh:
		if !ok {
			return 0, fmt.Errorf("SRTCP read stream is closed")
		}
		return res.len, nil
	}
}

// Close removes the ReadStream from the session and cleans up any associated state
func (r *ReadStreamSRTCP) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.isInited {
		return fmt.Errorf("ReadStreamSRTCP has not been inited")
	}

	select {
	case <-r.isClosed:
		return fmt.Errorf("ReadStreamSRTCP is already closed")
	default:
		close(r.readRetCh)
		r.session.removeReadStream(r.ssrc)
		return nil
	}
}

func (r *ReadStreamSRTCP) init(child streamSession, ssrc uint32) error {
	sessionSRTCP, ok := child.(*SessionSRTCP)

	r.mu.Lock()
	defer r.mu.Unlock()
	if !ok {
		return fmt.Errorf("ReadStreamSRTCP init failed type assertion")
	} else if r.isInited {
		return fmt.Errorf("ReadStreamSRTCP has already been inited")
	}

	r.session = sessionSRTCP
	r.ssrc = ssrc
	r.readCh = make(chan []byte)
	r.readRetCh = make(chan readResultSRTCP)
	r.isInited = true
	r.isClosed = make(chan bool)
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
func (w *WriteStreamSRTCP) WriteRTCP(header *rtcp.Header, payload []byte) (int, error) {
	headerRaw, err := header.Marshal()
	if err != nil {
		return 0, err
	}

	return w.session.write(append(headerRaw, payload...))
}

// Write encrypts and writes a full RTCP packets to the nextConn
func (w *WriteStreamSRTCP) Write(b []byte) (int, error) {
	return w.session.write(b)
}
