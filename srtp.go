package srtp

import (
	"crypto/cipher"
	"encoding/binary"

	"github.com/pions/rtp"
	"github.com/pkg/errors"
)

func (c *Context) decryptRTP(dst, encrypted []byte, header *rtp.Header) ([]byte, error) {
	dst = allocateIfMismatch(dst, encrypted)

	s := c.getSSRCState(header.SSRC)
	c.updateRolloverCount(header.SequenceNumber, s)

	pktWithROC := append(append([]byte{}, dst[:len(dst)-authTagSize]...), make([]byte, 4)...)
	binary.BigEndian.PutUint32(pktWithROC[len(pktWithROC)-4:], s.rolloverCounter)

	actualAuthTag := dst[len(dst)-authTagSize:]
	verified, err := c.verifyAuthTag(pktWithROC, actualAuthTag)
	if err != nil {
		return nil, err
	} else if !verified {
		return nil, errors.Errorf("Failed to verify auth tag")
	}

	counter := c.generateCounter(header.SequenceNumber, s.rolloverCounter, s.ssrc, c.srtpSessionSalt)
	stream := cipher.NewCTR(c.srtpBlock, counter[:])
	stream.XORKeyStream(dst[header.PayloadOffset:], dst[header.PayloadOffset:])

	return dst[:len(dst)-authTagSize], nil
}

// DecryptRTP decrypts a RTP packet with an encrypted payload
func (c *Context) DecryptRTP(dst, encrypted []byte, header *rtp.Header) ([]byte, error) {
	if header == nil {
		header = &rtp.Header{}
	}

	if err := header.Unmarshal(encrypted); err != nil {
		return nil, err
	}

	return c.decryptRTP(dst, encrypted, header)
}

// EncryptRTP encrypts a plaintext RTP packet, writing to the dst buffer provided.
// If the dst buffer does not have the capacity to hold `len(plaintext) + 10` bytes, a new one will be allocated.
// If a rtp.Header is provided, it will be Unmarshaled using the plaintext.
func (c *Context) EncryptRTP(dst []byte, plaintext []byte, header *rtp.Header) ([]byte, error) {
	// TODO(@lcurley) Potentially accept a *rtp.Packet to avoid this Unmarshal
	if header == nil {
		header = &rtp.Header{}
	}

	err := header.Unmarshal(plaintext)
	if err != nil {
		return nil, err
	}

	// Write to dst starting at this offset.
	offset := 0

	// Grow the given buffer to fit the output.
	// authTag = 10 bytes
	dst = growBufferSize(dst, len(plaintext)+10)

	s := c.getSSRCState(header.SSRC)
	c.updateRolloverCount(header.SequenceNumber, s)

	// Copy the header unencrypted.
	headerSize := header.PayloadOffset

	// Skip the copy if the two slices share memory addresses.
	if &dst[0] != &plaintext[0] {
		copy(dst[offset:], plaintext[:headerSize])
	}

	offset += headerSize

	// Encrypt the payload
	counter := c.generateCounter(header.SequenceNumber, s.rolloverCounter, s.ssrc, c.srtpSessionSalt)
	stream := cipher.NewCTR(c.srtpBlock, counter[:])
	stream.XORKeyStream(dst[offset:], plaintext[headerSize:])
	offset += len(plaintext) - headerSize

	// Write the rollover counter just for computing the auth tag.
	// We will overwrite it immediately afterwards.
	binary.BigEndian.PutUint32(dst[offset:], s.rolloverCounter)
	offset += 4

	// Generate the auth tag.
	authTag, err := c.generateAuthTag(dst[:offset], c.srtpSessionAuthTag)
	if err != nil {
		return nil, err
	}

	// Pop off the rollover counter.
	offset -= 4

	// Write the auth tag to the dest.
	copy(dst[offset:], authTag)

	return dst, nil
}
