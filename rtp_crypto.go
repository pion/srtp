package srtp

// RTPCrypto ...
type RTPCrypto interface {
	EncryptRTPBytes([]byte) ([]byte, error)
	DecryptRTPBytes([]byte) ([]byte, error)
	EncryptRTCPBytes([]byte) ([]byte, error)
	DecryptRTCPBytes([]byte) ([]byte, error)
}
