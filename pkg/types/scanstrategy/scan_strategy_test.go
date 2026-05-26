package scanstrategy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanStrategyString(t *testing.T) {
	tests := []struct {
		strategy ScanStrategy
		expected string
	}{
		{Auto, "auto"},
		{HostSpray, "host-spray"},
		{TemplateSpray, "template-spray"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.strategy.String())
		})
	}
}

func TestScanStrategyValues(t *testing.T) {
	require.Equal(t, ScanStrategy(0), Auto)
	require.Equal(t, ScanStrategy(1), HostSpray)
	require.Equal(t, ScanStrategy(2), TemplateSpray)
}
