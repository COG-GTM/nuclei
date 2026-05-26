package jsonexporter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	exporter, err := New(&Options{File: "test.json"})
	require.NoError(t, err)
	require.NotNil(t, exporter)
	require.Empty(t, exporter.rows)
}

func TestExport(t *testing.T) {
	exporter, err := New(&Options{File: "test.json"})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "CVE-2021-1234",
		Info:       model.Info{Name: "Test Vuln", SeverityHolder: severity.Holder{Severity: severity.High}},
		Host:       "example.com",
		Type:       "http",
		Matched:    "http://example.com/vulnerable",
	}
	err = exporter.Export(event)
	require.NoError(t, err)
	require.Len(t, exporter.rows, 1)
	require.Equal(t, "CVE-2021-1234", exporter.rows[0].TemplateID)
}

func TestExportOmitRaw(t *testing.T) {
	exporter, err := New(&Options{File: "test.json", OmitRaw: true})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "test-id",
		Request:    "GET / HTTP/1.1",
		Response:   "HTTP/1.1 200 OK",
	}
	err = exporter.Export(event)
	require.NoError(t, err)
	require.Equal(t, "", exporter.rows[0].Request)
	require.Equal(t, "", exporter.rows[0].Response)
}

func TestExportMultipleEvents(t *testing.T) {
	exporter, err := New(&Options{File: "test.json"})
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		event := &output.ResultEvent{
			TemplateID: "test-id",
			Host:       "example.com",
		}
		err = exporter.Export(event)
		require.NoError(t, err)
	}
	require.Len(t, exporter.rows, 5)
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "results.json")

	exporter, err := New(&Options{File: outFile})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "CVE-2021-5678",
		Info:       model.Info{Name: "Another Vuln", SeverityHolder: severity.Holder{Severity: severity.Medium}},
		Host:       "target.com",
		Type:       "http",
	}
	err = exporter.Export(event)
	require.NoError(t, err)

	err = exporter.Close()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var results []output.ResultEvent
	err = json.Unmarshal(data, &results)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, "CVE-2021-5678", results[0].TemplateID)
}

func TestCloseEmptyResults(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "empty.json")

	exporter, err := New(&Options{File: outFile})
	require.NoError(t, err)

	err = exporter.Close()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)

	var results []output.ResultEvent
	err = json.Unmarshal(data, &results)
	require.NoError(t, err)
	require.Empty(t, results)
}
