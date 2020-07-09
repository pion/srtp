package srtp

import (
	"testing"
)

func TestContextROC(t *testing.T) {
	c, err := CreateContext(make([]byte, 16), make([]byte, 14), cipherContextAlgo)
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
	c, err := CreateContext(make([]byte, 16), make([]byte, 14), cipherContextAlgo)
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
