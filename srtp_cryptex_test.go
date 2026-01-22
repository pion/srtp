// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"slices"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

type testRfcCryptex struct {
	profile    ProtectionProfile
	masterKey  []byte
	masterSalt []byte
	scenarios  map[cryptexScenario]testRfcCryptexScenario
}

type testRfcCryptexScenario struct {
	decrypted []byte
	encrypted []byte
}

type cryptexScenario int

const (
	cryptexScenarioOneByteExt cryptexScenario = iota
	cryptexScenarioTwoByteExt
	cryptexScenarioOneByteExtAndCsrc
	cryptexScenarioTwoByteExtAndCsrc
	cryptexScenarioEmptyOneByteExtAndCsrc
	cryptexScenarioEmptyTwoByteExtAndCsrc
)

// nolint:lll
func createRfcCryptexTestCiphers(t *testing.T) []testRfcCryptex {
	t.Helper()
	// Test Vectors from RFC 9335, Appendix A
	return []testRfcCryptex{
		// A.1. AES-CTR
		{
			profile:    ProtectionProfileAes128CmHmacSha1_80,
			masterKey:  fromHex(t, `e1f97a0d3e018be0d64fa32c06de4139`),
			masterSalt: fromHex(t, `0ec675ad498afeebb6960b3aabe6`),
			scenarios: map[cryptexScenario]testRfcCryptexScenario{
				// A.1.1. RTP Packet with One-Byte Header Extension
				cryptexScenarioOneByteExt: {
					decrypted: fromHex(t, `900f1235decafbadcafebabebede000151000200abababababababababababababababab`),
					encrypted: fromHex(t, `900f1235decafbadcafebabec0de0001eb92365251c3e036f8de27e9c27ee3e0b4651d9fbc4218a70244522f34a5`),
				},
				// A.1.2. RTP Packet with Two-Byte Header Extension
				cryptexScenarioTwoByteExt: {
					decrypted: fromHex(t, `900f1236decafbadcafebabe1000000105020002abababababababababababababababab`),
					encrypted: fromHex(t, `900f1236decafbadcafebabec2de00014ed9cc4e6a712b3096c5ca77339d4204ce0d77396cab69585fbce38194a5`),
				},
				// A.1.3. RTP Packet with One-Byte Header Extension and CSRC Fields
				cryptexScenarioOneByteExtAndCsrc: {
					decrypted: fromHex(t, `920f1238decafbadcafebabe0001e2400000b26ebede000151000200abababababababababababababababab`),
					encrypted: fromHex(t, `920f1238decafbadcafebabe8bb6e12b5cff16ddc0de000192838c8c09e58393e1de3a9a74734d6745671338c3acf11da2df8423bee0`),
				},
				// A.1.4. RTP Packet with Two-Byte Header Extension and CSRC Fields
				cryptexScenarioTwoByteExtAndCsrc: {
					decrypted: fromHex(t, `920f1239decafbadcafebabe0001e2400000b26e1000000105020002abababababababababababababababab`),
					encrypted: fromHex(t, `920f1239decafbadcafebabef70e513eb90b9b25c2de0001bbed4848faa644665f3d7f34125914e9f4d0ae923c6f479b95a0f7b53133`),
				},
				// A.1.5. RTP Packet with Empty One-Byte Header Extension and CSRC Fields
				cryptexScenarioEmptyOneByteExtAndCsrc: {
					decrypted: fromHex(t, `920f123adecafbadcafebabe0001e2400000b26ebede0000abababababababababababababababab`),
					encrypted: fromHex(t, `920f123adecafbadcafebabe7130b6abfe2ab0e3c0de0000e3d9f64b25c9e74cb4cf8e43fb92e3781c2c0ceab6b3a499a14c`),
				},
				// A.1.6. RTP Packet with Empty Two-Byte Header Extension and CSRC Fields
				cryptexScenarioEmptyTwoByteExtAndCsrc: {
					decrypted: fromHex(t, `920f123bdecafbadcafebabe0001e2400000b26e10000000abababababababababababababababab`),
					encrypted: fromHex(t, `920f123bdecafbadcafebabecbf24c124330e1c8c2de0000599dd45bc9d687b603e8b59d771fd38e88b170e0cd31e125eabe`),
				},
			},
		},
		// A.2. AES-GCM
		{
			profile:    ProtectionProfileAeadAes128Gcm,
			masterKey:  fromHex(t, `000102030405060708090a0b0c0d0e0f`),
			masterSalt: fromHex(t, `a0a1a2a3a4a5a6a7a8a9aaab`),
			scenarios: map[cryptexScenario]testRfcCryptexScenario{
				// A.2.1. RTP Packet with One-Byte Header Extension
				cryptexScenarioOneByteExt: {
					decrypted: fromHex(t, `900f1235decafbadcafebabebede000151000200abababababababababababababababab`),
					encrypted: fromHex(t, `900f1235decafbadcafebabec0de000139972dc9572c4d99e8fc355de743fb2e94f9d8ff54e72f4193bbc5c74ffab0fa9fa0fbeb`),
				},
				// A.2.2. RTP Packet with Two-Byte Header Extension
				cryptexScenarioTwoByteExt: {
					decrypted: fromHex(t, `900f1236decafbadcafebabe1000000105020002abababababababababababababababab`),
					encrypted: fromHex(t, `900f1236decafbadcafebabec2de0001bb75a4c545cd1f413bdb7daa2b1e3263de313667c963249081b35a65f5cb6c88b394235f`),
				},
				// A.2.3. RTP Packet with One-Byte Header Extension and CSRC Fields
				cryptexScenarioOneByteExtAndCsrc: {
					decrypted: fromHex(t, `920f1238decafbadcafebabe0001e2400000b26ebede000151000200abababababababababababababababab`),
					encrypted: fromHex(t, `920f1238decafbadcafebabe63bbccc4a7f695c4c0de00018ad7c71fac70a80c92866b4c6ba98546ef913586e95ffaaffe956885bb0647a8bc094ac8`),
				},
				// A.2.4. RTP Packet with Two-Byte Header Extension and CSRC Fields
				cryptexScenarioTwoByteExtAndCsrc: {
					decrypted: fromHex(t, `920f1239decafbadcafebabe0001e2400000b26e1000000105020002abababababababababababababababab`),
					encrypted: fromHex(t, `920f1239decafbadcafebabe3680524f8d312b00c2de0001c78d120038422bc111a7187a18246f980c059cc6bc9df8b626394eca344e4b05d80fea83`),
				},
				// A.2.5. RTP Packet with Empty One-Byte Header Extension and CSRC Fields
				cryptexScenarioEmptyOneByteExtAndCsrc: {
					decrypted: fromHex(t, `920f123adecafbadcafebabe0001e2400000b26ebede0000abababababababababababababababab`),
					encrypted: fromHex(t, `920f123adecafbadcafebabe15b6bb4337906fffc0de0000b7b964537a2b03ab7ba5389ce93317126b5d974df30c6884dcb651c5e120c1da`),
				},
				// A.2.6. RTP Packet with Empty Two-Byte Header Extension and CSRC Fields
				cryptexScenarioEmptyTwoByteExtAndCsrc: {
					decrypted: fromHex(t, `920f123bdecafbadcafebabe0001e2400000b26e10000000abababababababababababababababab`),
					encrypted: fromHex(t, `920f123bdecafbadcafebabedcb38c9e48bf95f4c2de000061ee432cf920317076613258d3ce4236c06ac429681ad08413512dc98b5207d8`),
				},
			},
		},
	}
}

func TestCryptexRFC(t *testing.T) {
	cryptexScenarioNames := map[cryptexScenario]string{
		cryptexScenarioOneByteExt:             "One-Byte Header Extension",
		cryptexScenarioTwoByteExt:             "Two-Byte Header Extension",
		cryptexScenarioOneByteExtAndCsrc:      "One-Byte Header Extension and CSRC Fields",
		cryptexScenarioTwoByteExtAndCsrc:      "Two-Byte Header Extension and CSRC Fields",
		cryptexScenarioEmptyOneByteExtAndCsrc: "Empty One-Byte Header Extension and CSRC Fields",
		cryptexScenarioEmptyTwoByteExtAndCsrc: "Empty Two-Byte Header Extension and CSRC Fields",
	}

	// Test using test vectors from RFC 9335, Appendix A
	for _, profile := range createRfcCryptexTestCiphers(t) {
		t.Run(profile.profile.String(), func(t *testing.T) {
			for scenario, data := range profile.scenarios {
				t.Run(cryptexScenarioNames[scenario], func(t *testing.T) {
					t.Run("Encrypt RTP", func(t *testing.T) {
						ctx, err := CreateContext(profile.masterKey, profile.masterSalt, profile.profile,
							Cryptex(CryptexModeEnabled))
						assert.NoError(t, err)

						t.Run("New Allocation", func(t *testing.T) {
							var header rtp.Header
							decrypted := slices.Clone(data.decrypted)
							actualEncrypted, err := ctx.EncryptRTP(nil, decrypted, &header)
							assert.NoError(t, err)
							assert.Equal(t, data.encrypted, actualEncrypted)

							assert.Equal(t, decrypted, data.decrypted,
								"The decrypted packet should not be modified during encryption")
						})

						t.Run("Same buffer", func(t *testing.T) {
							buffer := make([]byte, 0, 1000)
							src, dst := buffer, buffer
							src = append(src, data.decrypted...)
							assert.True(t, isSameBuffer(dst, src))

							var header rtp.Header
							actualEncrypted, err := ctx.EncryptRTP(dst, src, &header)
							assert.NoError(t, err)
							assert.Equal(t, data.encrypted, actualEncrypted)

							assert.True(t, isSameBuffer(actualEncrypted, src))
						})
					})

					t.Run("Decrypt RTP", func(t *testing.T) {
						ctx, err := CreateContext(profile.masterKey, profile.masterSalt, profile.profile,
							Cryptex(CryptexModeEnabled))
						assert.NoError(t, err)

						t.Run("New Allocation", func(t *testing.T) {
							var header rtp.Header
							encrypted := slices.Clone(data.encrypted)
							actualDecrypted, err := ctx.DecryptRTP(nil, encrypted, &header)
							assert.NoError(t, err)
							assert.Equal(t, data.decrypted, actualDecrypted)

							assert.Equal(t, encrypted, data.encrypted,
								"The encrypted packet should not be modified during decryption")

							assert.True(t, header.Extension, "Header should have an extension")
							if int(scenario)%2 == 0 {
								assert.Equal(t, uint16(rtp.ExtensionProfileOneByte), header.ExtensionProfile,
									"Header should have a one-byte extension profile")
							} else {
								assert.Equal(t, uint16(rtp.ExtensionProfileTwoByte), header.ExtensionProfile,
									"Header should have a two-byte extension profile")
							}
						})

						t.Run("Same buffer", func(t *testing.T) {
							buffer := make([]byte, 0, 1000)
							src, dst := buffer, buffer
							src = append(src, data.encrypted...)
							assert.True(t, isSameBuffer(dst, src))

							var header rtp.Header
							actualDecrypted, err := ctx.DecryptRTP(dst, src, &header)
							assert.NoError(t, err)
							assert.Equal(t, data.decrypted, actualDecrypted)

							assert.True(t, header.Extension, "Header should have an extension")
							if int(scenario)%2 == 0 {
								assert.Equal(t, uint16(rtp.ExtensionProfileOneByte), header.ExtensionProfile,
									"Header should have a one-byte extension profile")
							} else {
								assert.Equal(t, uint16(rtp.ExtensionProfileTwoByte), header.ExtensionProfile,
									"Header should have a two-byte extension profile")
							}

							assert.True(t, isSameBuffer(actualDecrypted, src))
						})
					})

					if scenario == cryptexScenarioEmptyOneByteExtAndCsrc {
						t.Run("Encrypt RTP with CSRCs and no ExtHdr", func(t *testing.T) {
							// When RTP packet has CSRCs but no header extension, we should add empty one-byte header
							// extension. Remove the header extension from the decrypted packet to simulate this.
							var rtpPacket rtp.Packet
							err := rtpPacket.Unmarshal(data.decrypted)
							assert.NoError(t, err)
							rtpPacket.Header.Extension = false
							rtpPacket.Header.ExtensionProfile = 0
							rtpPacket.Header.Extensions = nil
							rtpBytes, err := rtpPacket.Marshal()
							assert.NoError(t, err)

							ctx, err := CreateContext(profile.masterKey, profile.masterSalt, profile.profile,
								Cryptex(CryptexModeEnabled))
							assert.NoError(t, err)

							t.Run("New Allocation", func(t *testing.T) {
								var header rtp.Header
								decrypted := slices.Clone(rtpBytes)
								actualEncrypted, err := ctx.EncryptRTP(nil, decrypted, &header)
								assert.NoError(t, err)
								assert.Equal(t, data.encrypted, actualEncrypted)

								assert.Equal(t, decrypted, rtpBytes,
									"The decrypted packet should not be modified during encryption")
							})

							t.Run("Same buffer", func(t *testing.T) {
								buffer := make([]byte, 0, 1000)
								src, dst := buffer, buffer
								src = append(src, rtpBytes...)
								assert.True(t, isSameBuffer(dst, src))

								var header rtp.Header
								actualEncrypted, err := ctx.EncryptRTP(dst, src, &header)
								assert.NoError(t, err)
								assert.Equal(t, data.encrypted, actualEncrypted)

								assert.True(t, isSameBuffer(actualEncrypted, src))
							})
						})
					}
				})
			}
		})
	}
}

func TestCryptexUnsupportedHeaderExtension(t *testing.T) {
	// Test that Cryptex does not support header extensions other than one-byte and two-byte.
	ctx, err := CreateContext(make([]byte, 16), make([]byte, 14), ProtectionProfileAes128CmHmacSha1_80,
		Cryptex(CryptexModeEnabled))
	assert.NoError(t, err)

	rtpPacket := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			Extension:        true,
			ExtensionProfile: 1,
		},
	}
	err = rtpPacket.Header.SetExtension(0, []byte{0x01, 0x02, 0x03, 0x04})
	assert.NoError(t, err)
	rtpBytes, err := rtpPacket.Marshal()
	assert.NoError(t, err)

	_, err = ctx.EncryptRTP(nil, rtpBytes, nil)
	assert.ErrorIs(t, err, errUnsupportedHeaderExtension)
}

func TestCryptexModes(t *testing.T) {
	rtpPacket := rtp.Packet{
		Header: rtp.Header{
			Version:          2,
			Extension:        true,
			ExtensionProfile: rtp.ExtensionProfileOneByte,
		},
	}
	err := rtpPacket.Header.SetExtension(1, []byte{0x01, 0x02, 0x03, 0x04})
	assert.NoError(t, err)
	rtpBytes, err := rtpPacket.Marshal()
	assert.NoError(t, err)

	createCtx := func(t *testing.T, profile ProtectionProfile, opts ...ContextOption) *Context {
		t.Helper()
		keyLen, _ := profile.KeyLen()
		saltLen, _ := profile.SaltLen()
		ctx, err := CreateContext(make([]byte, keyLen), make([]byte, saltLen), profile, opts...)
		assert.NoError(t, err)

		return ctx
	}

	profiles := []ProtectionProfile{
		ProtectionProfileAes128CmHmacSha1_32,
		ProtectionProfileAes128CmHmacSha1_80,
		ProtectionProfileAes256CmHmacSha1_32,
		ProtectionProfileAes256CmHmacSha1_80,
		ProtectionProfileAeadAes128Gcm,
		ProtectionProfileAeadAes256Gcm,
	}
	for _, profile := range profiles {
		t.Run(profile.String(), func(t *testing.T) {
			ctxNoCryptex := createCtx(t, profile)
			ctxCryptex := createCtx(t, profile, Cryptex(CryptexModeEnabled))

			srtpNoCryptex, err := ctxNoCryptex.EncryptRTP(nil, rtpBytes, nil)
			assert.NoError(t, err)
			srtpCryptex, err := ctxCryptex.EncryptRTP(nil, rtpBytes, nil)
			assert.NoError(t, err)

			t.Run("Encrypt with Cryptex Disabled", func(t *testing.T) {
				ctx1 := createCtx(t, profile, Cryptex(CryptexModeDisabled))
				encrypted, err := ctx1.EncryptRTP(nil, rtpBytes, nil)
				assert.NoError(t, err)

				var header rtp.Packet
				err = header.Unmarshal(encrypted)
				assert.NoError(t, err)
				assert.Equal(t, uint16(rtp.ExtensionProfileOneByte), header.Header.ExtensionProfile)
			})

			t.Run("Decrypt with Cryptex Disabled", func(t *testing.T) {
				ctx1 := createCtx(t, profile, Cryptex(CryptexModeDisabled))
				_, err := ctx1.DecryptRTP(nil, srtpNoCryptex, nil)
				assert.NoError(t, err)

				_, err = ctx1.DecryptRTP(nil, srtpCryptex, nil)
				assert.ErrorIs(t, err, errCryptexDisabled)
			})

			t.Run("Encrypt with Cryptex Enabled", func(t *testing.T) {
				ctx1 := createCtx(t, profile, Cryptex(CryptexModeEnabled))
				encrypted, err := ctx1.EncryptRTP(nil, rtpBytes, nil)
				assert.NoError(t, err)

				var header rtp.Packet
				err = header.Unmarshal(encrypted)
				assert.NoError(t, err)
				assert.Equal(t, uint16(rtp.CryptexProfileOneByte), header.Header.ExtensionProfile)
			})

			t.Run("Decrypt with Cryptex Enabled", func(t *testing.T) {
				ctx1 := createCtx(t, profile, Cryptex(CryptexModeEnabled))
				_, err := ctx1.DecryptRTP(nil, srtpNoCryptex, nil)
				assert.NoError(t, err)

				_, err = ctx1.DecryptRTP(nil, srtpCryptex, nil)
				assert.NoError(t, err)
			})

			t.Run("Encrypt with Cryptex Required", func(t *testing.T) {
				ctx1 := createCtx(t, profile, Cryptex(CryptexModeRequired))
				encrypted, err := ctx1.EncryptRTP(nil, rtpBytes, nil)
				assert.NoError(t, err)

				var header rtp.Packet
				err = header.Unmarshal(encrypted)
				assert.NoError(t, err)
				assert.Equal(t, uint16(rtp.CryptexProfileOneByte), header.Header.ExtensionProfile)
			})

			t.Run("Decrypt with Cryptex Required", func(t *testing.T) {
				ctx1 := createCtx(t, profile, Cryptex(CryptexModeRequired))
				_, err := ctx1.DecryptRTP(nil, srtpNoCryptex, nil)
				assert.ErrorIs(t, err, errUnencryptedHeaderExtAndCSRCs)

				_, err = ctx1.DecryptRTP(nil, srtpCryptex, nil)
				assert.NoError(t, err)
			})
		})
	}
}
