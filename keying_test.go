// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

type mockKeyingMaterialExporter struct {
	exported []byte
}

func (m *mockKeyingMaterialExporter) ExportKeyingMaterial(label string, _ []byte, length int) ([]byte, error) {
	if label != labelExtractorDtlsSrtp {
		return nil, fmt.Errorf("%w: expected(%s) actual(%s)", errExporterWrongLabel, label, labelExtractorDtlsSrtp)
	}

	m.exported = make([]byte, length)
	if _, err := rand.Read(m.exported); err != nil {
		return nil, err
	}

	return m.exported, nil
}

func TestExtractSessionKeysFromDTLS(t *testing.T) {
	tt := []struct {
		config *Config
	}{
		{&Config{Profile: ProtectionProfileAes128CmHmacSha1_80}},
	}

	mockExporter := &mockKeyingMaterialExporter{}

	for i, tc := range tt {
		// Test client
		err := tc.config.ExtractSessionKeysFromDTLS(mockExporter, true)
		if err != nil {
			t.Errorf("failed to extract keys for %d-client: %v", i, err)
		}

		keys := tc.config.Keys
		clientMaterial := append([]byte{}, keys.LocalMasterKey...)
		clientMaterial = append(clientMaterial, keys.RemoteMasterKey...)
		clientMaterial = append(clientMaterial, keys.LocalMasterSalt...)
		clientMaterial = append(clientMaterial, keys.RemoteMasterSalt...)

		if !bytes.Equal(clientMaterial, mockExporter.exported) {
			t.Errorf(
				"material reconstruction failed for %d-client:\n%#v\nexpected\n%#v",
				i, clientMaterial, mockExporter.exported,
			)
		}

		// Test server
		err = tc.config.ExtractSessionKeysFromDTLS(mockExporter, false)
		if err != nil {
			t.Errorf("failed to extract keys for %d-server: %v", i, err)
		}

		keys = tc.config.Keys
		serverMaterial := append([]byte{}, keys.RemoteMasterKey...)
		serverMaterial = append(serverMaterial, keys.LocalMasterKey...)
		serverMaterial = append(serverMaterial, keys.RemoteMasterSalt...)
		serverMaterial = append(serverMaterial, keys.LocalMasterSalt...)

		if !bytes.Equal(serverMaterial, mockExporter.exported) {
			t.Errorf(
				"material reconstruction failed for %d-server:\n%#v\nexpected\n%#v",
				i, serverMaterial, mockExporter.exported,
			)
		}
	}
}
