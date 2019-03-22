// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aesctr_test

import (
	"crypto/aes"
	"testing"

	"github.com/pions/srtp/internal/aesctr"
)

func benchmarkAESStream(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [16]byte
	var iv [16]byte
	aes, err := aes.NewCipher(key[:])
	if err != nil {
		b.Fatal(err)
	}

	stream := aesctr.New(aes, iv[:])

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stream.XORKeyStream(buf, buf)
	}
}

// If we test exactly 1K blocks, we would generate exact multiples of
// the cipher's block size, and the cipher stream fragments would
// always be wordsize aligned, whereas non-aligned is a more typical
// use-case.
const almost1K = 1024 - 5
const almost8K = 8*1024 - 5

func BenchmarkAESCTR1K(b *testing.B) {
	benchmarkAESStream(b, make([]byte, almost1K))
}

func BenchmarkAESCTR8K(b *testing.B) {
	benchmarkAESStream(b, make([]byte, almost8K))
}
