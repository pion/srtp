// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aesctr_test

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/pions/srtp/internal/aesctr"
)

func TestEmptyPlaintext(t *testing.T) {
	var key [16]byte
	a, err := aes.NewCipher(key[:16])
	if err != nil {
		t.Fatal(err)
	}

	s := 16
	pt := make([]byte, s)
	ct := make([]byte, s)
	for i := 0; i < 16; i++ {
		pt[i], ct[i] = byte(i), byte(i)
	}

	assertEqual := func(name string, got, want []byte) {
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
	}

	iv := make([]byte, a.BlockSize())
	ctr := aesctr.New(a, iv)
	ctr.XORKeyStream(ct, pt[:0])
	assertEqual("CTR", ct, pt)
}
