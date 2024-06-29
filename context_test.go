// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContextROC(t *testing.T) {
	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := c.ROC(123); ok {
		t.Error("ROC must return false for unused SSRC")
	}
	c.SetROC(123, 100)
	roc, ok := c.ROC(123)
	if !ok {
		t.Fatal("ROC must return true for used SSRC")
	}
	if roc != 100 {
		t.Errorf("ROC is set to 100, but returned %d", roc)
	}
}

func TestContextIndex(t *testing.T) {
	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := c.Index(123); ok {
		t.Error("Index must return false for unused SSRC")
	}
	c.SetIndex(123, 100)
	index, ok := c.Index(123)
	if !ok {
		t.Fatal("Index must return true for used SSRC")
	}
	if index != 100 {
		t.Errorf("Index is set to 100, but returned %d", index)
	}
}

func TestContextWithoutMKI(t *testing.T) {
	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR)
	if err != nil {
		t.Fatal(err)
	}

	err = c.AddCipherForMKI(nil, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = c.AddCipherForMKI(make([]byte, 0), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = c.AddCipherForMKI(make([]byte, 4), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = c.SetSendMKI(nil)
	assert.Error(t, err)

	err = c.SetSendMKI(make([]byte, 0))
	assert.Error(t, err)

	err = c.RemoveMKI(nil)
	assert.Error(t, err)

	err = c.RemoveMKI(make([]byte, 0))
	assert.Error(t, err)

	err = c.RemoveMKI(make([]byte, 2))
	assert.Error(t, err)
}

func TestAddMKIToContextWithMKI(t *testing.T) {
	mki1 := []byte{1, 2, 3, 4}
	mki2 := []byte{2, 3, 4, 5}

	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR, MasterKeyIndicator(mki1))
	if err != nil {
		t.Fatal(err)
	}
	err = c.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	err = c.AddCipherForMKI(nil, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = c.AddCipherForMKI(make([]byte, 0), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = c.AddCipherForMKI(make([]byte, 3), make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = c.AddCipherForMKI(mki1, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)

	err = c.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	assert.Error(t, err)
}

func TestContextSetSendMKI(t *testing.T) {
	mki1 := []byte{1, 2, 3, 4}
	mki2 := []byte{2, 3, 4, 5}

	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR, MasterKeyIndicator(mki1))
	if err != nil {
		t.Fatal(err)
	}
	err = c.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	err = c.SetSendMKI(mki1)
	assert.NoError(t, err)

	err = c.SetSendMKI(mki2)
	assert.NoError(t, err)

	err = c.SetSendMKI(make([]byte, 4))
	assert.Error(t, err)
}

func TestContextRemoveMKI(t *testing.T) {
	mki1 := []byte{1, 2, 3, 4}
	mki2 := []byte{2, 3, 4, 5}
	mki3 := []byte{3, 4, 5, 6}

	c, err := CreateContext(make([]byte, 16), make([]byte, 14), profileCTR, MasterKeyIndicator(mki1))
	if err != nil {
		t.Fatal(err)
	}
	err = c.AddCipherForMKI(mki2, make([]byte, 16), make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}
	err = c.AddCipherForMKI(mki3, make([]byte, 16), make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	err = c.RemoveMKI(make([]byte, 4))
	assert.Error(t, err)

	err = c.RemoveMKI(mki1)
	assert.Error(t, err)

	err = c.SetSendMKI(mki3)
	assert.NoError(t, err)

	err = c.RemoveMKI(mki1)
	assert.NoError(t, err)

	err = c.RemoveMKI(mki2)
	assert.NoError(t, err)

	err = c.RemoveMKI(mki3)
	assert.Error(t, err)
}
