package stats

import (
	"testing"

	"github.com/logrusorgru/aurora"
	"github.com/stretchr/testify/require"
)

func TestNewTracker(t *testing.T) {
	tracker := NewTracker()
	require.NotNil(t, tracker)
}

func TestTrackerTrackStatusCode(t *testing.T) {
	tracker := NewTracker()

	tracker.TrackStatusCode("200")
	tracker.TrackStatusCode("200")
	tracker.TrackStatusCode("404")

	stats := tracker.GetStats()
	require.Equal(t, 2, stats.StatusCodeStats["200"])
	require.Equal(t, 1, stats.StatusCodeStats["404"])
}

func TestTrackerTrackErrorKind(t *testing.T) {
	tracker := NewTracker()

	tracker.TrackErrorKind("connection_refused")
	tracker.TrackErrorKind("connection_refused")
	tracker.TrackErrorKind("timeout")

	stats := tracker.GetStats()
	require.Equal(t, 2, stats.ErrorStats["connection_refused"])
	require.Equal(t, 1, stats.ErrorStats["timeout"])
}

func TestTrackerGetStatsEmpty(t *testing.T) {
	tracker := NewTracker()
	stats := tracker.GetStats()

	require.NotNil(t, stats)
	require.Empty(t, stats.StatusCodeStats)
	require.Empty(t, stats.ErrorStats)
	require.Empty(t, stats.WAFStats)
}

func TestGetTopN(t *testing.T) {
	m := map[string]int{
		"a": 10,
		"b": 5,
		"c": 20,
		"d": 1,
	}

	top2 := getTopN(m, 2)
	require.Len(t, top2, 2)
	require.Equal(t, "c", top2[0].Key)
	require.Equal(t, 20, top2[0].Value)
	require.Equal(t, "a", top2[1].Key)
	require.Equal(t, 10, top2[1].Value)
}

func TestGetTopNLargerThanMap(t *testing.T) {
	m := map[string]int{"a": 1}
	result := getTopN(m, 10)
	require.Len(t, result, 1)
}

func TestGetTopNEmpty(t *testing.T) {
	m := map[string]int{}
	result := getTopN(m, 5)
	require.Empty(t, result)
}

func TestGetStatusCodeColor(t *testing.T) {
	tests := []struct {
		code     string
		expected aurora.Color
	}{
		{"200", aurora.GreenFg},
		{"201", aurora.GreenFg},
		{"301", aurora.BlueFg},
		{"302", aurora.BlueFg},
		{"404", aurora.YellowFg},
		{"403", aurora.YellowFg},
		{"500", aurora.RedFg},
		{"503", aurora.RedFg},
		{"0", aurora.WhiteFg},
		{"invalid", aurora.WhiteFg},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			require.Equal(t, tc.expected, getStatusCodeColor(tc.code))
		})
	}
}
