package srtp

import (
	"crypto/cipher"
	"crypto/subtle"

	"github.com/pions/rtp"
	"github.com/pkg/errors"
)

func (c *Context) decryptRTP(dst []byte, ciphertext []byte, header *rtp.Header) ([]byte, error) {
	dst = growBufferSize(dst, len(ciphertext)-authTagSize)

	s := c.getSSRCState(header.SSRC)
	c.updateRolloverCount(header.SequenceNumber, s)

	// Split the auth tag and the cipher text into two parts.
	actualTag := ciphertext[len(ciphertext)-authTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-authTagSize]

	// Generate the auth tag we expect to see from the ciphertext.
	expectedTag, err := c.generateSrtpAuthTag(ciphertext, s.rolloverCounter)
	if err != nil {
		return nil, err
	}

	// See if the auth tag actually matches.
	// We use a constant time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, errors.Errorf("failed to verify auth tag")
	}

	// Write the plaintext header to the destination buffer.
	copy(dst, ciphertext[:header.PayloadOffset])

	// Decrypt the ciphertext for the payload.
	counter := c.generateCounter(header.SequenceNumber, s.rolloverCounter, s.ssrc, c.srtpSessionSalt)
	stream := cipher.NewCTR(c.srtpBlock, counter)
	stream.XORKeyStream(dst[header.PayloadOffset:], ciphertext[header.PayloadOffset:])

	return dst, nil
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

// EncryptRTP marshals and encrypts an RTP packet, writing to the dst buffer provided.
// If the dst buffer does not have the capacity to hold `len(plaintext) + 10` bytes, a new one will be allocated and returned.
// If the header is provided, it will be unmarshaled using the plaintext.
func (c *Context) EncryptRTP(dst []byte, plaintext []byte, header *rtp.Header) (ciphertext []byte, err error) {
	packet := &rtp.Packet{}

	err = packet.Header.Unmarshal(plaintext)
	if err != nil {
		return nil, err
	}

	packet.Payload = plaintext[packet.Header.PayloadOffset:]

	// If the header is provided, populate it with our unmarshaled data.
	if header != nil {
		*header = packet.Header
	}

	return c.encryptRTP(dst, packet)
}

// encryptRTP marshals and encrypts an RTP packet, writing to the dst buffer provided.
// If the dst buffer does not have the capacity to hold `len(plaintext) + 10` bytes, a new one will be allocated and returned.
// This is similar but slightly faster than the above method.
func (c *Context) encryptRTP(dst []byte, packet *rtp.Packet) (ciphertext []byte, err error) {
	// Write to dst starting at this offset.
	offset := 0

	// Grow the given buffer to fit the output.
	// authTag = 10 bytes
	dst = growBufferSize(dst, packet.MarshalSize()+10)

	s := c.getSSRCState(packet.Header.SSRC)
	c.updateRolloverCount(packet.Header.SequenceNumber, s)

	// Copy the header unencrypted.
	// The dst slicing is weird because MarshalTo uses append while others write directly.
	rawHeader, err := packet.Header.MarshalTo(dst[offset:offset])
	if err != nil {
		return nil, err
	}

	// Bad things would happen if this function actually appended, so just be safe.
	if &rawHeader[0] != &dst[offset] {
		return nil, errors.New("buffer too small")
	}

	offset += packet.Header.PayloadOffset

	// Encrypt the payload
	counter := c.generateCounter(packet.Header.SequenceNumber, s.rolloverCounter, s.ssrc, c.srtpSessionSalt)
	stream := cipher.NewCTR(c.srtpBlock, counter)
	stream.XORKeyStream(dst[offset:], packet.Payload)
	offset += len(packet.Payload)

	// Generate the auth tag.
	authTag, err := c.generateSrtpAuthTag(dst[:offset], s.rolloverCounter)
	if err != nil {
		return nil, err
	}

	// Write the auth tag to the dest.
	copy(dst[offset:], authTag)

	return dst, nil
}
