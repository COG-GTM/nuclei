package markdown

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no special chars", "simple-file.md", "simple-file.md"},
		{"with slashes", "path/to/file", "path_to_file"},
		{"with special chars", "file:name;test*bad", "file_name_test_bad"},
		{"with quotes", `he said "hello"`, "he_said__hello_"},
		{"with spaces", "file with spaces", "file_with_spaces"},
		{"truncates long names", func() string {
			s := ""
			for i := 0; i < 300; i++ {
				s += "a"
			}
			return s
		}(), func() string {
			s := ""
			for i := 0; i < 255; i++ {
				s += "a"
			}
			return s
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, sanitizeFilename(tt.input))
		})
	}
}

func TestCreateFileName(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID:  "CVE-2021-1234",
		Host:        "example.com",
		MatcherName: "version-check",
	}

	filename := createFileName(event)
	require.Contains(t, filename, "CVE-2021-1234")
	require.Contains(t, filename, "example.com")
	require.Contains(t, filename, "version-check")
	require.True(t, len(filename) > 0)
	require.Contains(t, filename, ".md")
}

func TestCreateFileNameWithoutMatcherOrExtractor(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID: "test-template",
		Host:       "target.com",
	}

	filename := createFileName(event)
	require.Contains(t, filename, "test-template")
	require.Contains(t, filename, "target.com")
	require.Contains(t, filename, ".md")
}

func TestCreateFileNameWithExtractorName(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID:    "test-template",
		Host:          "target.com",
		ExtractorName: "version-extractor",
	}

	filename := createFileName(event)
	require.Contains(t, filename, "test-template")
	require.Contains(t, filename, ".md")
}

func TestNewCreatesDirectoryAndIndex(t *testing.T) {
	tmpDir := t.TempDir()
	dir := filepath.Join(tmpDir, "md-report")

	exporter, err := New(&Options{Directory: dir})
	require.NoError(t, err)
	require.NotNil(t, exporter)

	indexPath := filepath.Join(dir, "index.md")
	_, err = os.Stat(indexPath)
	require.NoError(t, err)

	content, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "Hostname/IP")
	require.Contains(t, string(content), "Finding")
	require.Contains(t, string(content), "Severity")
}

func TestExport(t *testing.T) {
	tmpDir := t.TempDir()
	dir := filepath.Join(tmpDir, "md-export")

	exporter, err := New(&Options{Directory: dir})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "CVE-2021-1234",
		Info: model.Info{
			Name:           "Test Vulnerability",
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
		Host:    "example.com",
		Type:    "http",
		Matched: "http://example.com/vuln",
	}

	err = exporter.Export(event)
	require.NoError(t, err)

	// Verify index was updated
	indexContent, err := os.ReadFile(filepath.Join(dir, "index.md"))
	require.NoError(t, err)
	require.Contains(t, string(indexContent), "CVE-2021-1234")
}

func TestExportWithSortModeSeverity(t *testing.T) {
	tmpDir := t.TempDir()
	dir := filepath.Join(tmpDir, "md-sort")

	exporter, err := New(&Options{Directory: dir, SortMode: "severity"})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "CVE-2021-1234",
		Info: model.Info{
			Name:           "Test",
			SeverityHolder: severity.Holder{Severity: severity.Critical},
		},
		Host: "example.com",
	}

	err = exporter.Export(event)
	require.NoError(t, err)

	// Check that a severity subdirectory was created
	severityDir := filepath.Join(dir, "critical")
	_, err = os.Stat(severityDir)
	require.NoError(t, err)
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	exporter, err := New(&Options{Directory: tmpDir})
	require.NoError(t, err)

	err = exporter.Close()
	require.NoError(t, err)
}
