// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"testing"

	"github.com/pion/transport/v4/replaydetector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testReplayDetector is a minimal ReplayDetector used in factory option tests.
type testReplayDetector struct{}

func (d *testReplayDetector) Check(uint64) (func() bool, bool) {
	return func() bool { return true }, true
}

// constructedContext returns a fully constructed Context.
func constructedContext(t *testing.T) *Context {
	t.Helper()

	c, err := CreateContext(make([]byte, 16), make([]byte, 14), ProtectionProfileAes128CmHmacSha1_80)
	require.NoError(t, err)

	return c
}

func TestContextOptions(t *testing.T) {
	tests := []struct {
		name     string
		option   func() ContextOption
		validate func(t *testing.T, c *Context)
	}{
		{
			name:   "SRTPReplayProtection",
			option: func() ContextOption { return SRTPReplayProtection(128) },
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.NotNil(t, c.newSRTPReplayDetector)
				assert.NotNil(t, c.newSRTPReplayDetector())
			},
		},
		{
			name:   "SRTCPReplayProtection",
			option: func() ContextOption { return SRTCPReplayProtection(128) },
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.NotNil(t, c.newSRTCPReplayDetector)
				assert.NotNil(t, c.newSRTCPReplayDetector())
			},
		},
		{
			name: "SRTPNoReplayProtection",
			option: func() ContextOption {
				return func(c *Context) error {
					c.newSRTPReplayDetector = func() replaydetector.ReplayDetector { return &testReplayDetector{} }

					return SRTPNoReplayProtection()(c)
				}
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				require.NotNil(t, c.newSRTPReplayDetector)
				_, ok := c.newSRTPReplayDetector().(*nopReplayDetector)
				assert.True(t, ok)
			},
		},
		{
			name: "SRTCPNoReplayProtection",
			option: func() ContextOption {
				return func(c *Context) error {
					c.newSRTCPReplayDetector = func() replaydetector.ReplayDetector { return &testReplayDetector{} }

					return SRTCPNoReplayProtection()(c)
				}
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				require.NotNil(t, c.newSRTCPReplayDetector)
				_, ok := c.newSRTCPReplayDetector().(*nopReplayDetector)
				assert.True(t, ok)
			},
		},
		{
			name: "SRTPReplayDetectorFactory",
			option: func() ContextOption {
				return SRTPReplayDetectorFactory(func() replaydetector.ReplayDetector { return &testReplayDetector{} })
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				require.NotNil(t, c.newSRTPReplayDetector)
				_, ok := c.newSRTPReplayDetector().(*testReplayDetector)
				assert.True(t, ok)
			},
		},
		{
			name: "SRTCPReplayDetectorFactory",
			option: func() ContextOption {
				return SRTCPReplayDetectorFactory(func() replaydetector.ReplayDetector { return &testReplayDetector{} })
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				require.NotNil(t, c.newSRTCPReplayDetector)
				_, ok := c.newSRTCPReplayDetector().(*testReplayDetector)
				assert.True(t, ok)
			},
		},
		{
			name:   "MasterKeyIndicator",
			option: func() ContextOption { return MasterKeyIndicator([]byte{0x01, 0x02, 0x03, 0x04}) },
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, c.sendMKI)
			},
		},
		{
			name: "SRTPEncryption",
			option: func() ContextOption {
				return func(c *Context) error {
					c.encryptSRTP = false

					return SRTPEncryption()(c)
				}
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.True(t, c.encryptSRTP)
			},
		},
		{
			name: "SRTPNoEncryption",
			option: func() ContextOption {
				return func(c *Context) error {
					c.encryptSRTP = true

					return SRTPNoEncryption()(c)
				}
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.False(t, c.encryptSRTP)
			},
		},
		{
			name: "SRTCPEncryption",
			option: func() ContextOption {
				return func(c *Context) error {
					c.encryptSRTCP = false

					return SRTCPEncryption()(c)
				}
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.True(t, c.encryptSRTCP)
			},
		},
		{
			name: "SRTCPNoEncryption",
			option: func() ContextOption {
				return func(c *Context) error {
					c.encryptSRTCP = true

					return SRTCPNoEncryption()(c)
				}
			},
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.False(t, c.encryptSRTCP)
			},
		},
		{
			name:   "RolloverCounterCarryingTransform",
			option: func() ContextOption { return RolloverCounterCarryingTransform(RCCMode2, 10) },
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.Equal(t, RCCMode2, c.rccMode)
				assert.Equal(t, uint16(10), c.rocTransmitRate)
			},
		},
		{
			name:   "SRTPAuthenticationTagLength",
			option: func() ContextOption { return SRTPAuthenticationTagLength(8) },
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				require.NotNil(t, c.authTagRTPLen)
				assert.Equal(t, 8, *c.authTagRTPLen)
			},
		},
		{
			name:   "Cryptex",
			option: func() ContextOption { return Cryptex(CryptexModeEnabled) },
			validate: func(t *testing.T, c *Context) {
				t.Helper()
				assert.Equal(t, CryptexModeEnabled, c.cryptexMode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("sets value", func(t *testing.T) {
				c := &Context{}
				require.NoError(t, tt.option()(c))
				tt.validate(t, c)
			})

			t.Run("constructed error", func(t *testing.T) {
				ctx := constructedContext(t)
				err := tt.option()(ctx)
				assert.ErrorIs(t, err, ErrContextOptionNotUpdatable)
			})
		})
	}
}
