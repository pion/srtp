package srtp

import (
	"context"
)

type readStream interface {
	init(child streamSession, ssrc uint32) error

	Read(ctx context.Context, buf []byte) (int, error)
	GetSSRC() uint32
}
