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
	stream := cipher.NewCTR(c.srtpBlock, counter)
	stream.XORKeyStream(dst[offset:], plaintext[headerSize:])
	offset += len(plaintext) - headerSize

	// Generate the auth tag.
	authTag, err := c.generateSrtpAuthTag(dst[:offset], s.rolloverCounter)
	if err != nil {
		return nil, err
	}

	// Write the auth tag to the dest.
	copy(dst[offset:], authTag)

	return dst, nil
}
