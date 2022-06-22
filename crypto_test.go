package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func xorBytesCTRReference(block cipher.Block, iv []byte, dst, src []byte) {
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)
}

func TestXorBytesCTR(t *testing.T) {
	for keysize := 16; keysize < 64; keysize *= 2 {
		key := make([]byte, keysize)
		_, err := rand.Read(key) //nolint: gosec
		require.NoError(t, err)

		block, err := aes.NewCipher(key)
		require.NoError(t, err)

		iv := make([]byte, block.BlockSize())
		for i := 0; i < 1500; i++ {
			src := make([]byte, i)
			dst := make([]byte, i)
			reference := make([]byte, i)
			_, err = rand.Read(iv) //nolint: gosec
			require.NoError(t, err)

			_, err = rand.Read(src) //nolint: gosec
			require.NoError(t, err)

			assert.NoError(t, xorBytesCTR(block, iv, dst, src))
			xorBytesCTRReference(block, iv, reference, src)
			require.Equal(t, dst, reference)

			// test overlap
			assert.NoError(t, xorBytesCTR(block, iv, dst, dst))
			xorBytesCTRReference(block, iv, reference, reference)
			require.Equal(t, dst, reference)
		}
	}
}

func TestXorBytesCTRInvalidIvLength(t *testing.T) {
	key := make([]byte, 16)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)

	src := make([]byte, 1024)
	dst := make([]byte, 1024)

	test := func(iv []byte) {
		assert.Error(t, errBadIVLength, xorBytesCTR(block, iv, dst, src))
	}

	test(make([]byte, block.BlockSize()-1))
	test(make([]byte, block.BlockSize()+1))
}
