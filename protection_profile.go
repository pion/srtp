package srtp

import "fmt"

// ProtectionProfile specifies Cipher and AuthTag details, similar to TLS cipher suite
type ProtectionProfile uint16

// Supported protection profiles
const (
	ProtectionProfileAes128CmHmacSha1_80 ProtectionProfile = 0x0001
)

func (p ProtectionProfile) keyLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_80:
		return 16, nil
	default:
		return 0, fmt.Errorf("no such ProtectionProfile %#v", p)
	}
}

func (p ProtectionProfile) saltLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_80:
		return 14, nil
	default:
		return 0, fmt.Errorf("no such ProtectionProfile %#v", p)
	}
}

func (p ProtectionProfile) authTagLen() (int, error) {
	switch p {
	case ProtectionProfileAes128CmHmacSha1_80:
		return 10, nil
	default:
		return 0, fmt.Errorf("no such ProtectionProfile %#v", p)
	}
}
