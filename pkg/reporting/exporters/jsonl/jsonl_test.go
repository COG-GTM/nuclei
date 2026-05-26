package jsonl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

func newTestEvent(templateID, host string) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: templateID,
		Info:       model.Info{Name: "Test", SeverityHolder: severity.Holder{Severity: severity.High}},
		Host:       host,
		Type:       "http",
	}
}

func TestNew(t *testing.T) {
	exporter, err := New(&Options{File: "test.jsonl"})
	require.NoError(t, err)
	require.NotNil(t, exporter)
	require.Empty(t, exporter.rows)
}

func TestExport(t *testing.T) {
	exporter, err := New(&Options{File: "test.jsonl"})
	require.NoError(t, err)

	err = exporter.Export(newTestEvent("CVE-2021-1234", "example.com"))
	require.NoError(t, err)
	require.Len(t, exporter.rows, 1)
}

func TestExportOmitRaw(t *testing.T) {
	exporter, err := New(&Options{File: "test.jsonl", OmitRaw: true})
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

func TestExportWithBatching(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "batch.jsonl")

	exporter, err := New(&Options{File: outFile, BatchSize: 3})
	require.NoError(t, err)

	// Add 2 events — should not flush yet
	err = exporter.Export(newTestEvent("test-1", "host1.com"))
	require.NoError(t, err)
	err = exporter.Export(newTestEvent("test-2", "host2.com"))
	require.NoError(t, err)
	require.Len(t, exporter.rows, 2)

	// Add a 3rd event — should trigger a flush
	err = exporter.Export(newTestEvent("test-3", "host3.com"))
	require.NoError(t, err)
	require.Empty(t, exporter.rows)

	// Verify file content
	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3)

	for _, line := range lines {
		var result output.ResultEvent
		err = json.Unmarshal([]byte(line), &result)
		require.NoError(t, err)
	}
}

func TestCloseWritesRemainingRows(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "close.jsonl")

	exporter, err := New(&Options{File: outFile})
	require.NoError(t, err)

	err = exporter.Export(newTestEvent("CVE-2021-0001", "a.com"))
	require.NoError(t, err)
	err = exporter.Export(newTestEvent("CVE-2021-0002", "b.com"))
	require.NoError(t, err)

	err = exporter.Close()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2)
}

func TestWriteRowsMultipleBatches(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "multi-batch.jsonl")

	exporter, err := New(&Options{File: outFile, BatchSize: 2})
	require.NoError(t, err)

	// First batch
	err = exporter.Export(newTestEvent("t-1", "h1.com"))
	require.NoError(t, err)
	err = exporter.Export(newTestEvent("t-2", "h2.com"))
	require.NoError(t, err)

	// Second batch
	err = exporter.Export(newTestEvent("t-3", "h3.com"))
	require.NoError(t, err)
	err = exporter.Export(newTestEvent("t-4", "h4.com"))
	require.NoError(t, err)

	// Close writes remaining
	err = exporter.Close()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 4)
}
