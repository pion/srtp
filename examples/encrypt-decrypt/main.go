// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

func main() {
	// Key+Salt is used to encrypt packets
	key := make([]byte, 16)
	salt := make([]byte, 12)

	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	// In this example we are using the same Key+Salt for both sides
	// In production it would be better to use a different key+salt on either side
	srtpConfig := &srtp.Config{
		Profile: srtp.ProtectionProfileAeadAes128Gcm,
		Keys: srtp.SessionKeys{
			LocalMasterKey:   key,
			LocalMasterSalt:  salt,
			RemoteMasterKey:  key,
			RemoteMasterSalt: salt,
		},
	}

	serverConn, clientConn := net.Pipe()
	writerSession, err := srtp.NewSessionSRTP(serverConn, srtpConfig)
	if err != nil {
		panic(err)
	}
	readerSession, err := srtp.NewSessionSRTP(clientConn, srtpConfig)
	if err != nil {
		panic(err)
	}

	writeStream, err := writerSession.OpenWriteStream()
	if err != nil {
		panic(err)
	}

	const ssrc = 0xDEADBEEF
	readStream, err := readerSession.OpenReadStream(ssrc)
	if err != nil {
		panic(err)
	}

	buff := make([]byte, 17)
	for seq := uint16(1); seq <= 3; seq++ {
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    111,
				SequenceNumber: seq,
				Timestamp:      123456 + uint32(seq*160),
				SSRC:           ssrc,
			},
			Payload: []byte{byte(seq), byte(seq), byte(seq), byte(seq), byte(seq)},
		}

		fmt.Printf("encrypted RTP seq=%d ts=%d payload=%X\n", pkt.SequenceNumber, pkt.Timestamp, pkt.Payload)

		if _, err := writeStream.WriteRTP(&pkt.Header, pkt.Payload); err != nil {
			panic(err)
		}

		_, header, err := readStream.ReadRTP(buff)
		if err != nil {
			panic(err)
		}

		fmt.Printf("decrypted RTP seq=%d ts=%d payload=%X\n\n", header.SequenceNumber, header.Timestamp, buff[12:])
	}
}
