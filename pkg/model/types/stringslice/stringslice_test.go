package stringslice

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestStringSliceToSliceFromString(t *testing.T) {
	ss := New("single")
	result := ss.ToSlice()
	require.Equal(t, []string{"single"}, result)
}

func TestStringSliceToSliceFromSlice(t *testing.T) {
	ss := New([]string{"a", "b", "c"})
	result := ss.ToSlice()
	require.Equal(t, []string{"a", "b", "c"}, result)
}

func TestStringSliceToSliceFromNil(t *testing.T) {
	ss := New(nil)
	result := ss.ToSlice()
	require.Equal(t, []string{}, result)
}

func TestStringSliceToSlicePanicsOnBadType(t *testing.T) {
	ss := New(42)
	require.Panics(t, func() {
		ss.ToSlice()
	})
}

func TestStringSliceIsEmpty(t *testing.T) {
	require.True(t, (&StringSlice{Value: nil}).IsEmpty())
	require.True(t, (&StringSlice{Value: []string{}}).IsEmpty())
	require.False(t, (&StringSlice{Value: "test"}).IsEmpty())
	require.False(t, (&StringSlice{Value: ""}).IsEmpty()) // single empty string still has length 1
	require.False(t, (&StringSlice{Value: []string{"a"}}).IsEmpty())
}

func TestStringSliceString(t *testing.T) {
	ss := New([]string{"http", "dns", "ssl"})
	require.Equal(t, "http, dns, ssl", ss.String())
}

func TestStringSliceNormalize(t *testing.T) {
	ss := StringSlice{}
	require.Equal(t, "test", ss.Normalize("  Test  "))
	require.Equal(t, "hello", ss.Normalize("HELLO"))
}

func TestStringSliceUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"array", `["HTTP","DNS"]`, []string{"http", "dns"}},
		{"string", `"http,dns"`, []string{"http", "dns"}},
		{"empty_string", `""`, []string{}},
		{"empty_array", `[]`, []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ss StringSlice
			err := ss.UnmarshalJSON([]byte(tc.input))
			require.NoError(t, err)
			require.Equal(t, tc.expected, ss.ToSlice())
		})
	}
}

func TestStringSliceMarshalJSON(t *testing.T) {
	ss := New([]string{"a", "b"})
	data, err := ss.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, `["a","b"]`, string(data))
}

func TestStringSliceUnmarshalYAML(t *testing.T) {
	yamlData := `- HTTP
- DNS
`
	var ss StringSlice
	err := yaml.Unmarshal([]byte(yamlData), &ss)
	require.NoError(t, err)
	require.Equal(t, []string{"http", "dns"}, ss.ToSlice())
}

func TestStringSliceMarshalYAML(t *testing.T) {
	ss := New([]string{"http", "dns"})
	result, err := ss.MarshalYAML()
	require.NoError(t, err)
	require.Equal(t, []string{"http", "dns"}, result)
}

func TestRawStringSliceNoNormalization(t *testing.T) {
	raw := NewRawStringSlice([]string{"HTTP", "DNS"})
	require.Equal(t, "HTTP", raw.Normalize("HTTP"))
	result := raw.ToSlice()
	require.Equal(t, []string{"HTTP", "DNS"}, result)
}

func TestRawStringSliceUnmarshalYAML(t *testing.T) {
	yamlData := `- HTTP
- DNS
`
	var raw RawStringSlice
	err := yaml.Unmarshal([]byte(yamlData), &raw)
	require.NoError(t, err)
	// RawStringSlice should preserve case
	require.Equal(t, []string{"HTTP", "DNS"}, raw.ToSlice())
}
