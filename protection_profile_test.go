// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidProtectionProfile(t *testing.T) {
	var invalidProtectionProfile ProtectionProfile

	_, err := invalidProtectionProfile.KeyLen()
	assert.Error(t, err)

	_, err = invalidProtectionProfile.SaltLen()
	assert.Error(t, err)
}
