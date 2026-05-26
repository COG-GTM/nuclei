package utils

import (
	"bytes"
	"testing"

	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/require"
)

func TestIsBlank(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"", true},
		{" ", true},
		{"\t", true},
		{"\n", true},
		{"  \t\n  ", true},
		{"a", false},
		{" a ", false},
		{"hello world", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.expected, IsBlank(tc.input))
		})
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"https://example.com", true},
		{"http://example.com/path", true},
		{"ftp://files.example.com", true},
		{"example.com", false},
		{"/path/to/file", false},
		{"", false},
		{"not a url", false},
		{"https://", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			require.Equal(t, tc.expected, IsURL(tc.input))
		})
	}
}

func TestStringSliceContains(t *testing.T) {
	slice := []string{"HTTP", "dns", "Network"}

	require.True(t, StringSliceContains(slice, "http"))
	require.True(t, StringSliceContains(slice, "HTTP"))
	require.True(t, StringSliceContains(slice, "DNS"))
	require.True(t, StringSliceContains(slice, "network"))
	require.False(t, StringSliceContains(slice, "ssl"))
	require.False(t, StringSliceContains(nil, "http"))
	require.False(t, StringSliceContains([]string{}, "http"))
}

func TestMapHash(t *testing.T) {
	m1 := map[string]string{"a": "1", "b": "2"}
	m2 := map[string]string{"b": "2", "a": "1"}
	m3 := map[string]string{"a": "1", "b": "3"}

	hash1 := MapHash(m1)
	hash2 := MapHash(m2)
	hash3 := MapHash(m3)

	// same content regardless of insertion order should produce same hash
	require.Equal(t, hash1, hash2)
	// different content should produce different hash
	require.NotEqual(t, hash1, hash3)
}

func TestMapHashEmpty(t *testing.T) {
	empty := map[string]int{}
	hash := MapHash(empty)
	require.NotZero(t, hash)
}

func TestMapHashIntKeys(t *testing.T) {
	m1 := map[int]string{1: "a", 2: "b"}
	m2 := map[int]string{2: "b", 1: "a"}
	require.Equal(t, MapHash(m1), MapHash(m2))
}

func TestCaptureWriter(t *testing.T) {
	buf := &bytes.Buffer{}
	w := &CaptureWriter{Buffer: buf}

	w.Write([]byte("test message"), levels.LevelInfo)
	require.Equal(t, "test message", buf.String())

	w.Write([]byte(" more data"), levels.LevelWarning)
	require.Equal(t, "test message more data", buf.String())
}

func TestInsertionOrderedStringMapSet(t *testing.T) {
	m := NewEmptyInsertionOrderedStringMap(3)
	m.Set("first", "1")
	m.Set("second", "2")
	m.Set("third", "3")

	require.Equal(t, 3, m.Len())

	var keys []string
	m.ForEach(func(key string, data interface{}) {
		keys = append(keys, key)
	})
	require.Equal(t, []string{"first", "second", "third"}, keys)
}

func TestInsertionOrderedStringMapOverwrite(t *testing.T) {
	m := NewEmptyInsertionOrderedStringMap(2)
	m.Set("key", "original")
	m.Set("key", "updated")

	require.Equal(t, 1, m.Len())

	var values []interface{}
	m.ForEach(func(key string, data interface{}) {
		values = append(values, data)
	})
	require.Equal(t, []interface{}{"updated"}, values)
}

func TestNewInsertionOrderedStringMapFromMap(t *testing.T) {
	input := map[string]interface{}{
		"alpha": "a",
		"beta":  "b",
	}
	m := NewInsertionOrderedStringMap(input)
	require.Equal(t, 2, m.Len())
}

func TestInsertionOrderedStringMapUnmarshalJSON(t *testing.T) {
	data := []byte(`{"name":"nuclei","version":"3.0"}`)
	var m InsertionOrderedStringMap
	err := m.UnmarshalJSON(data)
	require.NoError(t, err)
	require.Equal(t, 2, m.Len())
}

func TestToStringConversions(t *testing.T) {
	tests := []struct {
		input    interface{}
		expected interface{}
	}{
		{nil, ""},
		{"hello", "hello"},
		{true, "true"},
		{false, "false"},
		{float64(3.14), "3.14"},
		{float32(2.5), "2.5"},
		{int(42), "42"},
		{int64(100), "100"},
		{int32(50), "50"},
		{int16(25), "25"},
		{int8(10), "10"},
		{uint(7), "7"},
		{uint64(8), "8"},
		{uint32(9), "9"},
		{uint16(11), "11"},
		{uint8(12), "12"},
		{[]byte("bytes"), "bytes"},
	}

	for _, tc := range tests {
		result := toString(tc.input)
		require.Equal(t, tc.expected, result)
	}
}

func TestToStringSlice(t *testing.T) {
	input := []interface{}{"a", "b"}
	result := toString(input)
	require.Equal(t, input, result)
}

func TestToStringStruct(t *testing.T) {
	type custom struct{ Name string }
	result := toString(custom{Name: "test"})
	require.Equal(t, "{test}", result)
}
