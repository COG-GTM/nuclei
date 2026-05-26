package types

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

func TestProtocolTypeString(t *testing.T) {
	tests := []struct {
		protocol ProtocolType
		expected string
	}{
		{DNSProtocol, "dns"},
		{FileProtocol, "file"},
		{HTTPProtocol, "http"},
		{HeadlessProtocol, "headless"},
		{NetworkProtocol, "tcp"},
		{WorkflowProtocol, "workflow"},
		{SSLProtocol, "ssl"},
		{WebsocketProtocol, "websocket"},
		{WHOISProtocol, "whois"},
		{CodeProtocol, "code"},
		{JavascriptProtocol, "javascript"},
		{InvalidProtocol, "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.protocol.String())
		})
	}
}

func TestToProtocolType(t *testing.T) {
	tests := []struct {
		input    string
		expected ProtocolType
		hasError bool
	}{
		{"dns", DNSProtocol, false},
		{"DNS", DNSProtocol, false},
		{" http ", HTTPProtocol, false},
		{"ssl", SSLProtocol, false},
		{"tcp", NetworkProtocol, false},
		{"javascript", JavascriptProtocol, false},
		{"nonexistent", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := toProtocolType(tt.input)
			if tt.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetSupportedProtocolTypes(t *testing.T) {
	types := GetSupportedProtocolTypes()
	require.NotEmpty(t, types)
	require.Contains(t, types, HTTPProtocol)
	require.Contains(t, types, DNSProtocol)
	require.NotContains(t, types, InvalidProtocol)
}

func TestSupportedProtocolsStrings(t *testing.T) {
	strings := SupportedProtocolsStrings()
	require.NotEmpty(t, strings)
	require.Contains(t, strings, "http")
	require.Contains(t, strings, "dns")
}

func TestTypeHolderMarshalJSON(t *testing.T) {
	holder := &TypeHolder{ProtocolType: HTTPProtocol}
	data, err := holder.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, `"http"`, string(data))
}

func TestTypeHolderMarshalYAML(t *testing.T) {
	holder := TypeHolder{ProtocolType: DNSProtocol}
	val, err := holder.MarshalYAML()
	require.NoError(t, err)
	require.Equal(t, "dns", val)
}

func TestProtocolTypesMarshalJSON(t *testing.T) {
	types := ProtocolTypes{HTTPProtocol, DNSProtocol}
	data, err := types.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, `["http","dns"]`, string(data))
}

func TestProtocolTypesString(t *testing.T) {
	types := ProtocolTypes{HTTPProtocol, SSLProtocol, DNSProtocol}
	require.Equal(t, "http, ssl, dns", types.String())
}

func TestProtocolTypesSet(t *testing.T) {
	var types ProtocolTypes
	err := types.Set("http")
	require.NoError(t, err)
	require.Len(t, types, 1)
	require.Equal(t, HTTPProtocol, types[0])
}

func TestProtocolTypesSetInvalid(t *testing.T) {
	var types ProtocolTypes
	err := types.Set("nonexistent")
	require.Error(t, err)
}

func TestNormalizeValue(t *testing.T) {
	require.Equal(t, "http", normalizeValue("  HTTP  "))
	require.Equal(t, "dns", normalizeValue("DNS"))
	require.Equal(t, "ssl", normalizeValue("ssl"))
}

func TestTypeHolderJSONRoundTrip(t *testing.T) {
	original := &TypeHolder{ProtocolType: HTTPProtocol}
	data, err := json.Marshal(original)
	require.NoError(t, err)
	require.Equal(t, `"http"`, string(data))
}
