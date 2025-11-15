// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import "github.com/pion/transport/v3"

type readStream interface {
	init(child streamSession, ssrc uint32) error

	Read(buf []byte) (int, error)

	ReadWithAttributes(b []byte, attr *transport.PacketAttributes) (int, error)

	GetSSRC() uint32
}
