// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

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
