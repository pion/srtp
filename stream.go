package srtp

import "github.com/pion/transport/connctx"

type readStream interface {
	init(child streamSession, ssrc uint32) error

	connctx.Reader
	GetSSRC() uint32
}
