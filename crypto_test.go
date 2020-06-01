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

func TestXorBytesBufferSize(t *testing.T) {
	a := []byte{3}
	b := []byte{5, 6}
	dst := make([]byte, 3)

	xorBytes(dst, a, b)
	require.Equal(t, dst, []byte{6, 0, 0})

	xorBytes(dst, b, a)
	require.Equal(t, dst, []byte{6, 0, 0})

	a = []byte{1, 1, 1, 1}
	b = []byte{2, 2, 2, 2}
	dst = make([]byte, 3)

	xorBytes(dst, a, b)
	require.Equal(t, dst, []byte{3, 3, 3})
}

func benchmarkXorBytesCTR(b *testing.B, size int) {
	key := make([]byte, 16)
	_, err := rand.Read(key) //nolint: gosec
	require.NoError(b, err)

	block, err := aes.NewCipher(key)
	require.NoError(b, err)

	iv := make([]byte, 16)
	src := make([]byte, 1024)
	dst := make([]byte, 1024)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rand.Read(iv) //nolint: gosec
		require.NoError(b, err)

		_, err = rand.Read(src) //nolint: gosec
		require.NoError(b, err)

		assert.NoError(b, xorBytesCTR(block, iv, dst, src))
	}
}

func BenchmarkXorBytesCTR14(b *testing.B) {
	benchmarkXorBytesCTR(b, 14)
}

func BenchmarkXorBytesCTR140(b *testing.B) {
	benchmarkXorBytesCTR(b, 140)
}

func BenchmarkXorBytesCTR1400(b *testing.B) {
	benchmarkXorBytesCTR(b, 1400)
}

func benchmarkXorBytesCTRReference(b *testing.B, size int) {
	key := make([]byte, 16)
	_, err := rand.Read(key) //nolint: gosec
	if err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatalf("NewCipher: %v", err)
	}
	iv := make([]byte, 16)
	src := make([]byte, 1024)
	dst := make([]byte, 1024)

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rand.Read(iv) //nolint: gosec
		require.NoError(b, err)

		_, err = rand.Read(src) //nolint: gosec
		require.NoError(b, err)

		xorBytesCTRReference(block, iv, dst, src)
	}
}

func BenchmarkXorBytesCTR14Reference(b *testing.B) {
	benchmarkXorBytesCTRReference(b, 14)
}

func BenchmarkXorBytesCTR140Reference(b *testing.B) {
	benchmarkXorBytesCTRReference(b, 140)
}

func BenchmarkXorBytesCTR1400Reference(b *testing.B) {
	benchmarkXorBytesCTRReference(b, 1400)
}
