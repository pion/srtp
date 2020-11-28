package srtp

import (
	"context"
)

// ConnCtx is a Conn controlled by context.Context instead of SetDeadline.
type ConnCtx interface {
	ReadContext(context.Context, []byte) (int, error)
	WriteContext(context.Context, []byte) (int, error)
	Close() error
}
