package srtp

import (
	"errors"
	"fmt"
)

var errDuplicated = errors.New("duplicated packet")

type errorDuplicated struct {
	Proto string // srtp or srtcp
	SSRC  uint32
	Index uint32 // sequence number or index
}

func (e *errorDuplicated) Error() string {
	return fmt.Sprintf("%s ssrc=%d index=%d: %v", e.Proto, e.SSRC, e.Index, errDuplicated)
}

func (e *errorDuplicated) Unwrap() error {
	return errDuplicated
}
