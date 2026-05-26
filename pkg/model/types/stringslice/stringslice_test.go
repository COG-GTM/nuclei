package stringslice

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

func TestStringSliceToSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{name: "single string", input: "hello", expected: []string{"hello"}},
		{name: "string slice", input: []string{"a", "b", "c"}, expected: []string{"a", "b", "c"}},
		{name: "nil value", input: nil, expected: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := StringSlice{Value: tt.input}
			require.Equal(t, tt.expected, ss.ToSlice())
		})
	}
}

func TestStringSliceToSlicePanicsOnInvalidType(t *testing.T) {
	ss := StringSlice{Value: 42}
	require.Panics(t, func() { ss.ToSlice() })
}

func TestStringSliceIsEmpty(t *testing.T) {
	require.True(t, (&StringSlice{Value: nil}).IsEmpty())
	require.True(t, (&StringSlice{Value: []string{}}).IsEmpty())
	require.False(t, (&StringSlice{Value: "hello"}).IsEmpty())
	require.False(t, (&StringSlice{Value: []string{"a"}}).IsEmpty())
}

func TestStringSliceString(t *testing.T) {
	require.Equal(t, "a, b", StringSlice{Value: []string{"a", "b"}}.String())
	require.Equal(t, "hello", StringSlice{Value: "hello"}.String())
	require.Equal(t, "", StringSlice{Value: nil}.String())
}

func TestStringSliceNormalize(t *testing.T) {
	ss := StringSlice{}
	require.Equal(t, "hello", ss.Normalize("  Hello  "))
	require.Equal(t, "test", ss.Normalize("TEST"))
	require.Equal(t, "", ss.Normalize("  "))
}

func TestStringSliceNew(t *testing.T) {
	ss := New("test")
	require.Equal(t, "test", ss.Value)

	ss2 := New([]string{"a", "b"})
	require.Equal(t, []string{"a", "b"}, ss2.Value)
}

func TestStringSliceJSONMarshalUnmarshal(t *testing.T) {
	t.Run("marshal slice", func(t *testing.T) {
		ss := StringSlice{Value: []string{"a", "b"}}
		data, err := ss.MarshalJSON()
		require.NoError(t, err)
		require.Equal(t, `["a","b"]`, string(data))
	})

	t.Run("unmarshal from array", func(t *testing.T) {
		var ss StringSlice
		err := ss.UnmarshalJSON([]byte(`["CVE-2021-1234", "RCE"]`))
		require.NoError(t, err)
		require.Equal(t, []string{"cve-2021-1234", "rce"}, ss.ToSlice())
	})

	t.Run("unmarshal from string with comma", func(t *testing.T) {
		var ss StringSlice
		err := ss.UnmarshalJSON([]byte(`"info,low"`))
		require.NoError(t, err)
		require.Equal(t, []string{"info", "low"}, ss.ToSlice())
	})

	t.Run("unmarshal from empty string", func(t *testing.T) {
		var ss StringSlice
		err := ss.UnmarshalJSON([]byte(`""`))
		require.NoError(t, err)
		require.Empty(t, ss.ToSlice())
	})

	t.Run("unmarshal invalid json", func(t *testing.T) {
		var ss StringSlice
		err := ss.UnmarshalJSON([]byte(`{invalid`))
		require.Error(t, err)
	})
}

func TestStringSliceJSONRoundTrip(t *testing.T) {
	original := StringSlice{Value: []string{"cve", "misc", "xss"}}
	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded StringSlice
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, original.ToSlice(), decoded.ToSlice())
}

func TestRawStringSlicePreservesCase(t *testing.T) {
	raw := NewRawStringSlice("Hello World")
	require.Equal(t, "Hello World", raw.Normalize("Hello World"))
}

func TestNewRawStringSlice(t *testing.T) {
	raw := NewRawStringSlice([]string{"A", "B"})
	require.Equal(t, []string{"A", "B"}, raw.ToSlice())
}
