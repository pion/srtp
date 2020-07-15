package srtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidProtectionProfile(t *testing.T) {
	var invalidProtectionProfile ProtectionProfile

	_, err := invalidProtectionProfile.keyLen()
	assert.Error(t, err)

	_, err = invalidProtectionProfile.saltLen()
	assert.Error(t, err)
}
