// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Counter (CTR) mode.

// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.

// See NIST SP 800-38A, pp 13-15

package aesctr

import (
	"crypto/aes"
	"crypto/cipher"
)

// Must be multiple of aes.BlockSize
const streamBufferSize = 32 * aes.BlockSize

// Stream is a CTR cipher stream optimized for AES.
type Stream struct {
	b       cipher.Block
	ctr     [aes.BlockSize]byte
	out     [streamBufferSize]byte
	outUsed int
}

// New returns a Stream which encrypts/decrypts using the given Block in
// counter mode. The length of iv must be the same as aes.BlockSize.
func New(block cipher.Block, iv []byte) (x *Stream) {
	if len(iv) != aes.BlockSize {
		panic("aesctr.New: IV length must equal AES block size")
	}

	x = &Stream{b: block}
	x.outUsed = len(x.out)
	copy(x.ctr[:], iv)

	return x
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src must overlap entirely or not at all.
//
// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
//
// Multiple calls to XORKeyStream behave as if the concatenation of
// the src buffers was passed in a single run. That is, Stream
// maintains state and does not reset at each XORKeyStream call.
func (x *Stream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("aesctr: output smaller than input")
	}

	if inexactOverlap(dst[:len(src)], src) {
		panic("aesctr: invalid buffer overlap")
	}

	// Use the remainder of x.out
	if x.outUsed < len(x.out) {
		n := xorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}

	for len(src) > 0 {
		// If we still have more data to encrypt, we have to generate some more data in x.out
		for i := 0; i < len(x.out); i += aes.BlockSize {
			x.b.Encrypt(x.out[i:], x.ctr[:])

			// Increment counter
			for i := len(x.ctr) - 1; i >= 0; i-- {
				x.ctr[i]++
				if x.ctr[i] != 0 {
					break
				}
			}
		}

		n := xorBytes(dst, src, x.out[:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed = n
	}
}

// Reset will reset the cipher to the given IV.
func (x *Stream) Reset(iv []byte) {
	if len(iv) != aes.BlockSize {
		panic("aesctr.Reset: IV length must equal block size")
	}

	copy(x.ctr[:], iv)
	x.outUsed = len(x.out)
}
