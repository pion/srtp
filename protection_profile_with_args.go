// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

// ProtectionProfileWithArgs is a wrapper around ProtectionProfile that allows to
// specify additional arguments for the profile.
type ProtectionProfileWithArgs struct {
	ProtectionProfile
	authTagRTPLen *int
}

// AuthTagRTPLen returns length of RTP authentication tag in bytes for AES protection profiles.
// For AEAD ones it returns zero.
func (p ProtectionProfileWithArgs) AuthTagRTPLen() (int, error) {
	if p.authTagRTPLen != nil {
		return *p.authTagRTPLen, nil
	}

	return p.ProtectionProfile.AuthTagRTPLen()
}
