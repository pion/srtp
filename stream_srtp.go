// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/transport/v5/packetio"
)

// Limit the buffer size to 1MB.
const srtpBufferSize = 1000 * 1000

// packetBuffer wraps packetio.Buffer to implement io.ReadWriteCloser.
type packetBuffer struct {
	*packetio.Buffer
}

func (b *packetBuffer) Read(buf []byte) (int, error) {
	n, _, err := b.Buffer.Read(buf, nil)

	return n, err
}

func (b *packetBuffer) Write(buf []byte) (int, error) {
	return b.Buffer.Write(buf, nil)
}

func (b *packetBuffer) ReadWithAttributes(buf []byte, attrs packetio.Attributes) (int, packetio.Attributes, error) {
	return b.Buffer.Read(buf, attrs)
}

func (b *packetBuffer) WriteWithAttributes(buf []byte, attrs packetio.Attributes) (int, error) {
	return b.Buffer.Write(buf, attrs)
}

type peekedPacket struct {
	payload    []byte
	attributes packetio.Attributes
}

// ReadStreamSRTP receives decrypted RTP for an SSRC and its optional RTX SSRC.
type ReadStreamSRTP struct {
	mu sync.Mutex

	isClosed bool

	session  *SessionSRTP
	ssrc     uint32
	isInited bool

	rtxSSRC   *uint32
	rtxStream *ReadStreamSRTP
	isRTX     bool

	buffer        io.ReadWriteCloser
	peekedPackets []peekedPacket
}

// Used by getOrCreateReadStream.
func newReadStreamSRTP() readStream {
	return &ReadStreamSRTP{}
}

func (r *ReadStreamSRTP) init(child streamSession, ssrc uint32) error {
	sessionSRTP, ok := child.(*SessionSRTP)

	r.mu.Lock()
	defer r.mu.Unlock()

	if !ok {
		return errFailedTypeAssertion
	} else if r.isInited {
		return errStreamAlreadyInited
	}

	r.session = sessionSRTP
	r.ssrc = ssrc
	r.isInited = true

	// Create a buffer with a 1MB limit
	if r.session.bufferFactory != nil {
		r.buffer = r.session.bufferFactory(packetio.RTPBufferPacket, ssrc)
	} else {
		buff := &packetBuffer{Buffer: packetio.NewBuffer()}
		buff.SetLimitSize(srtpBufferSize)
		r.buffer = buff
	}

	return nil
}

func (r *ReadStreamSRTP) write(buf []byte, attrs packetio.Attributes) error {
	_, err := writeWithAttributes(r.buffer, buf, attrs)

	if errors.Is(err, packetio.ErrFull) {
		// Silently drop data when the buffer is full.
		return nil
	}

	return err
}

// Peek reads and decrypts full RTP packet from the nextConn.
// It is then buffered so that a call to `Read` will return it.
func (r *ReadStreamSRTP) Peek(buf []byte) (n int, err error) {
	var attrs packetio.Attributes
	n, attrs, err = readWithAttributes(r.buffer, buf, nil)
	if err == nil {
		r.peekedPackets = append(r.peekedPackets, peekedPacket{slices.Clone(buf[:n]), attrs})
	}

	return
}

// Read reads and decrypts full RTP packet from the nextConn.
func (r *ReadStreamSRTP) Read(buf []byte) (int, error) {
	n, _, err := r.ReadWithAttributes(buf, nil)

	return n, err
}

// ReadWithAttributes reads a decrypted RTP packet and its attributes.
// It replaces attrs with the packet's attributes, reusing its storage when possible.
func (r *ReadStreamSRTP) ReadWithAttributes(buf []byte, attrs packetio.Attributes) (int, packetio.Attributes, error) {
	if len(r.peekedPackets) != 0 {
		clear(attrs)
		packet := r.peekedPackets[0]
		if len(packet.payload) > len(buf) {
			return 0, attrs[:0], io.ErrShortBuffer
		}

		n := copy(buf, packet.payload)
		attrs = append(attrs[:0], packet.attributes...)
		r.peekedPackets[0] = peekedPacket{}
		r.peekedPackets = r.peekedPackets[1:]

		return n, attrs, nil
	}

	return readWithAttributes(r.buffer, buf, attrs)
}

// ReadRTP reads and decrypts full RTP packet and its header from the nextConn.
func (r *ReadStreamSRTP) ReadRTP(buf []byte) (int, *rtp.Header, error) {
	n, err := r.Read(buf)
	if err != nil {
		return 0, nil, err
	}

	header := &rtp.Header{}

	_, err = header.Unmarshal(buf[:n])
	if err != nil {
		return 0, nil, err
	}

	return n, header, nil
}

// SetReadDeadline sets the deadline for the Read operation.
// Setting to zero means no deadline.
func (r *ReadStreamSRTP) SetReadDeadline(t time.Time) error {
	if b, ok := r.buffer.(interface {
		SetReadDeadline(time.Time) error
	}); ok {
		return b.SetReadDeadline(t)
	}

	return nil
}

// SetRTX routes one repair SSRC to this stream without rewriting its packets.
// Authentication and replay protection remain separate for each SSRC.
// Repeating the same SSRC is a no-op; changing it is not supported.
// If the repair stream already exists, stop reading it (including Peek) first.
// Its read deadline is cleared and the session closes it on shutdown.
// Closing this stream also closes the repair stream.
func (r *ReadStreamSRTP) SetRTX(ssrc uint32) error { //nolint:cyclop
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isInited {
		return errStreamNotInited
	}
	session := r.session
	session.readStreamsLock.Lock()
	defer session.readStreamsLock.Unlock()

	if session.readStreamsClosed || session.readStreams[r.ssrc] != r {
		return errStreamAlreadyClosed
	}
	if r.rtxSSRC != nil && *r.rtxSSRC == ssrc {
		return nil
	}
	if r.isRTX || r.rtxSSRC != nil || ssrc == r.ssrc {
		return errStreamAlreadyInited
	}
	existing := session.readStreams[ssrc]
	rtx, ok := existing.(*ReadStreamSRTP)
	if existing != nil && (!ok || rtx.isRTX || rtx.rtxSSRC != nil) {
		return errStreamAlreadyInited
	}
	if rtx != nil {
		if err := rtx.SetReadDeadline(time.Time{}); err != nil {
			return err
		}
	}
	r.rtxSSRC, r.rtxStream = &ssrc, rtx
	if rtx == nil {
		session.readStreams[ssrc] = r

		return nil
	}
	rtx.isRTX = true
	go func() {
		buffer := make([]byte, 8192)
		for {
			n, attributes, err := rtx.ReadWithAttributes(buffer, nil)
			if err != nil {
				return
			}
			if err = r.write(buffer[:n], attributes); err != nil {
				return
			}
		}
	}()

	return nil
}

// Close removes the ReadStream from the session and cleans up any associated state.
func (r *ReadStreamSRTP) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.isInited {
		return errStreamNotInited
	}

	if r.isClosed {
		return nil
	}

	err := r.buffer.Close()
	if err != nil {
		return err
	}
	if r.rtxStream != nil {
		if err = r.rtxStream.Close(); err != nil {
			return err
		}
	} else if r.rtxSSRC != nil {
		r.session.removeReadStream(*r.rtxSSRC)
	}

	r.session.removeReadStream(r.ssrc)
	r.isClosed = true

	return nil
}

// GetSSRC returns the SSRC we are demuxing for.
func (r *ReadStreamSRTP) GetSSRC() uint32 {
	return r.ssrc
}

// WriteStreamSRTP is stream for a single Session that is used to encrypt RTP.
type WriteStreamSRTP struct {
	session *SessionSRTP
}

// WriteRTP encrypts a RTP packet and writes to the connection.
func (w *WriteStreamSRTP) WriteRTP(header *rtp.Header, payload []byte) (int, error) {
	return w.session.writeRTP(header, payload)
}

// Write encrypts and writes a full RTP packets to the nextConn.
func (w *WriteStreamSRTP) Write(b []byte) (int, error) {
	return w.session.write(b)
}

// SetWriteDeadline sets the deadline for the Write operation.
// Setting to zero means no deadline.
func (w *WriteStreamSRTP) SetWriteDeadline(t time.Time) error {
	return w.session.setWriteDeadline(t)
}
