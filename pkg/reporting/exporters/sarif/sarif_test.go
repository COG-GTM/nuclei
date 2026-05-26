package sarif

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	sarifLib "github.com/projectdiscovery/sarif"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	exporter, err := New(&Options{File: "test.sarif"})
	require.NoError(t, err)
	require.NotNil(t, exporter)
	require.NotNil(t, exporter.sarif)
	require.Empty(t, exporter.rules)
	require.NotNil(t, exporter.rulemap)
}

func TestGetSeverity(t *testing.T) {
	exporter, _ := New(&Options{File: "test.sarif"})

	tests := []struct {
		input         string
		expectedLevel sarifLib.Level
		expectedScore string
	}{
		{"critical", sarifLib.Error, "9.4"},
		{"high", sarifLib.Error, "8"},
		{"medium", sarifLib.Note, "5"},
		{"low", sarifLib.Note, "2"},
		{"info", sarifLib.None, "1"},
		{"unknown", sarifLib.None, "9.5"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, score := exporter.getSeverity(tt.input)
			require.Equal(t, tt.expectedLevel, level)
			require.Equal(t, tt.expectedScore, score)
		})
	}
}

func TestExport(t *testing.T) {
	exporter, err := New(&Options{File: "test.sarif"})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "CVE-2021-1234",
		Info: model.Info{
			Name:           "Test Vulnerability",
			Description:    "A test vulnerability description",
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
		Host:    "https://example.com",
		Path:    "/vulnerable",
		Type:    "http",
		Matched: "https://example.com/vulnerable",
	}

	err = exporter.Export(event)
	require.NoError(t, err)
	require.Len(t, exporter.rules, 1)
	require.Equal(t, "CVE-2021-1234", exporter.rules[0].Id)
}

func TestExportDuplicateRuleID(t *testing.T) {
	exporter, err := New(&Options{File: "test.sarif"})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		event := &output.ResultEvent{
			TemplateID: "CVE-2021-1234",
			Info: model.Info{
				Name:           "Test Vulnerability",
				SeverityHolder: severity.Holder{Severity: severity.High},
			},
			Host: "https://example.com",
		}
		err = exporter.Export(event)
		require.NoError(t, err)
	}
	require.Len(t, exporter.rules, 1)
}

func TestExportMultipleRules(t *testing.T) {
	exporter, err := New(&Options{File: "test.sarif"})
	require.NoError(t, err)

	templates := []string{"CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"}
	for _, tmplID := range templates {
		event := &output.ResultEvent{
			TemplateID: tmplID,
			Info: model.Info{
				Name:           tmplID,
				SeverityHolder: severity.Holder{Severity: severity.Medium},
			},
			Host: "target.com",
		}
		err = exporter.Export(event)
		require.NoError(t, err)
	}
	require.Len(t, exporter.rules, 3)
}

func TestCloseWithResults(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "report.sarif")

	exporter, err := New(&Options{File: outFile})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "CVE-2021-9999",
		Info: model.Info{
			Name:           "SARIF Test",
			Description:    "Description",
			SeverityHolder: severity.Holder{Severity: severity.Critical},
		},
		Host: "target.com",
		Path: "/path",
	}
	err = exporter.Export(event)
	require.NoError(t, err)

	err = exporter.Close()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	require.Contains(t, string(data), "CVE-2021-9999")
	require.Contains(t, string(data), "Nuclei")
}

func TestCloseWithNoResults(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "empty.sarif")

	exporter, err := New(&Options{File: outFile})
	require.NoError(t, err)

	err = exporter.Close()
	require.NoError(t, err)

	_, err = os.Stat(outFile)
	require.True(t, os.IsNotExist(err))
}
