package contextargs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewMetaInput(t *testing.T) {
	mi := NewMetaInput()
	require.NotNil(t, mi)
	require.NotNil(t, mi.mu)
}

func TestMetaInputTarget(t *testing.T) {
	t.Run("returns Input when no ReqResp", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com"
		require.Equal(t, "https://example.com", mi.Target())
	})

	t.Run("returns Input for empty metainput", func(t *testing.T) {
		mi := NewMetaInput()
		require.Equal(t, "", mi.Target())
	})
}

func TestMetaInputPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"with explicit port", "https://example.com:8443", "8443"},
		{"without port", "https://example.com", ""},
		{"invalid url", "not-a-url", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := NewMetaInput()
			mi.Input = tt.input
			require.Equal(t, tt.expected, mi.Port())
		})
	}
}

func TestMetaInputAddress(t *testing.T) {
	t.Run("https default port", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com"
		addr := mi.Address()
		require.Equal(t, "example.com:443", addr)
	})

	t.Run("http default port", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "http://example.com"
		addr := mi.Address()
		require.Equal(t, "example.com:80", addr)
	})

	t.Run("with explicit port", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com:9443"
		addr := mi.Address()
		require.Equal(t, "example.com:9443", addr)
	})

	t.Run("with custom IP", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com"
		mi.CustomIP = "1.2.3.4"
		addr := mi.Address()
		require.Equal(t, "1.2.3.4:443", addr)
	})

	t.Run("invalid input with custom IP", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "not-a-url"
		mi.CustomIP = "10.0.0.1"
		addr := mi.Address()
		require.Contains(t, addr, "10.0.0.1")
	})
}

func TestMetaInputID(t *testing.T) {
	t.Run("simple input", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com"
		require.Equal(t, "https://example.com", mi.ID())
	})

	t.Run("with custom IP", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com"
		mi.CustomIP = "1.2.3.4"
		require.Equal(t, "https://example.com-1.2.3.4", mi.ID())
	})
}

func TestMetaInputClone(t *testing.T) {
	mi := NewMetaInput()
	mi.Input = "https://example.com"
	mi.CustomIP = "1.2.3.4"

	clone := mi.Clone()
	require.Equal(t, mi.Input, clone.Input)
	require.Equal(t, mi.CustomIP, clone.CustomIP)
	require.NotSame(t, mi, clone)

	// Mutating clone should not affect original
	clone.Input = "https://other.com"
	require.Equal(t, "https://example.com", mi.Input)
}

func TestMetaInputPrettyPrint(t *testing.T) {
	t.Run("simple input", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com"
		require.Equal(t, "https://example.com", mi.PrettyPrint())
	})

	t.Run("with custom IP", func(t *testing.T) {
		mi := NewMetaInput()
		mi.Input = "https://example.com"
		mi.CustomIP = "1.2.3.4"
		require.Equal(t, "https://example.com [1.2.3.4]", mi.PrettyPrint())
	})
}

func TestMetaInputMarshalUnmarshal(t *testing.T) {
	mi := NewMetaInput()
	mi.Input = "https://example.com"
	mi.CustomIP = "1.2.3.4"

	marshaled, err := mi.MarshalString()
	require.NoError(t, err)
	require.NotEmpty(t, marshaled)

	decoded := NewMetaInput()
	err = decoded.Unmarshal(marshaled)
	require.NoError(t, err)
	require.Equal(t, mi.Input, decoded.Input)
	require.Equal(t, mi.CustomIP, decoded.CustomIP)
}

func TestMetaInputMustMarshalString(t *testing.T) {
	mi := NewMetaInput()
	mi.Input = "https://test.com"
	result := mi.MustMarshalString()
	require.NotEmpty(t, result)
}

func TestMetaInputMustMarshalBytes(t *testing.T) {
	mi := NewMetaInput()
	mi.Input = "https://test.com"
	result := mi.MustMarshalBytes()
	require.NotEmpty(t, result)
}

func TestMetaInputGetScanHash(t *testing.T) {
	mi := NewMetaInput()
	mi.Input = "https://example.com"

	hash1 := mi.GetScanHash("template-1")
	require.NotEmpty(t, hash1)

	// Same inputs should produce the same hash (cached)
	hash2 := mi.GetScanHash("template-2")
	require.Equal(t, hash1, hash2)
}

func TestMetaInputGetScanHashDifferentInputs(t *testing.T) {
	mi1 := NewMetaInput()
	mi1.Input = "https://example.com"

	mi2 := NewMetaInput()
	mi2.Input = "https://other.com"

	hash1 := mi1.GetScanHash("template-1")
	hash2 := mi2.GetScanHash("template-1")
	require.NotEqual(t, hash1, hash2)
}
