package disk

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func TestNewFSCatalog(t *testing.T) {
	memFS := fstest.MapFS{
		"templates/test.yaml": &fstest.MapFile{Data: []byte("id: test")},
	}
	catalog := NewFSCatalog(memFS, "templates")
	require.NotNil(t, catalog)
	require.Equal(t, "templates", catalog.templatesDirectory)
	require.NotNil(t, catalog.templatesFS)
}

func TestOpenFileWithFS(t *testing.T) {
	content := []byte("id: test-template\ninfo:\n  name: Test")
	memFS := fstest.MapFS{
		"test.yaml": &fstest.MapFile{Data: content},
	}

	catalog := NewFSCatalog(memFS, ".")
	reader, err := catalog.OpenFile("test.yaml")
	require.NoError(t, err)
	defer reader.Close()

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, content, data)
}

func TestOpenFileWithDisk(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.yaml")
	content := []byte("id: disk-test")
	err := os.WriteFile(testFile, content, 0644)
	require.NoError(t, err)

	catalog := &DiskCatalog{templatesDirectory: tmpDir}
	reader, err := catalog.OpenFile(testFile)
	require.NoError(t, err)
	defer reader.Close()

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, content, data)
}

func TestOpenFileNotFound(t *testing.T) {
	catalog := &DiskCatalog{templatesDirectory: t.TempDir()}
	_, err := catalog.OpenFile("/nonexistent/path/file.yaml")
	require.Error(t, err)
}

func TestOpenFileWithFSNotFound(t *testing.T) {
	memFS := fstest.MapFS{}
	catalog := NewFSCatalog(memFS, ".")
	_, err := catalog.OpenFile("nonexistent.yaml")
	require.Error(t, err)
}

func TestGetTemplatePathWithFS(t *testing.T) {
	memFS := fstest.MapFS{
		"vuln.yaml":              &fstest.MapFile{Data: []byte("id: vuln")},
		"subdir/another.yaml":    &fstest.MapFile{Data: []byte("id: another")},
		"subdir/notatemplate.go": &fstest.MapFile{Data: []byte("package main")},
	}

	catalog := NewFSCatalog(memFS, "")

	t.Run("single file", func(t *testing.T) {
		paths, err := catalog.GetTemplatePath("vuln.yaml")
		require.NoError(t, err)
		require.Equal(t, []string{"vuln.yaml"}, paths)
	})

	t.Run("directory listing", func(t *testing.T) {
		paths, err := catalog.GetTemplatePath("subdir")
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.Contains(t, paths[0], "another.yaml")
	})

	t.Run("glob pattern", func(t *testing.T) {
		paths, err := catalog.GetTemplatePath("*.yaml")
		require.NoError(t, err)
		require.NotEmpty(t, paths)
	})
}

func TestGetTemplatePathNotFound(t *testing.T) {
	memFS := fstest.MapFS{}
	catalog := NewFSCatalog(memFS, "")
	_, err := catalog.GetTemplatePath("nonexistent.yaml")
	require.Error(t, err)
}

func TestGetTemplatesPathWithFS(t *testing.T) {
	memFS := fstest.MapFS{
		"a.yaml": &fstest.MapFile{Data: []byte("id: a")},
		"b.yaml": &fstest.MapFile{Data: []byte("id: b")},
	}

	catalog := NewFSCatalog(memFS, "")
	paths, erred := catalog.GetTemplatesPath([]string{"a.yaml", "b.yaml"})
	require.Empty(t, erred)
	require.Len(t, paths, 2)
}

func TestGetTemplatesPathDeduplicates(t *testing.T) {
	memFS := fstest.MapFS{
		"a.yaml": &fstest.MapFile{Data: []byte("id: a")},
	}

	catalog := NewFSCatalog(memFS, "")
	paths, _ := catalog.GetTemplatesPath([]string{"a.yaml", "a.yaml"})
	require.Len(t, paths, 1)
}

func TestGetTemplatesPathWithDisk(t *testing.T) {
	tmpDir := t.TempDir()

	for _, name := range []string{"t1.yaml", "t2.yaml"} {
		err := os.WriteFile(filepath.Join(tmpDir, name), []byte("id: "+name), 0644)
		require.NoError(t, err)
	}

	catalog := &DiskCatalog{templatesDirectory: tmpDir}
	paths, erred := catalog.GetTemplatesPath([]string{
		filepath.Join(tmpDir, "t1.yaml"),
		filepath.Join(tmpDir, "t2.yaml"),
	})
	require.Empty(t, erred)
	require.Len(t, paths, 2)
}

func TestResolvePathAbsolute(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.yaml")
	err := os.WriteFile(testFile, []byte("id: test"), 0644)
	require.NoError(t, err)

	catalog := &DiskCatalog{templatesDirectory: tmpDir}
	resolved, err := catalog.ResolvePath(testFile, "")
	require.NoError(t, err)
	require.Equal(t, testFile, resolved)
}

func TestResolvePathWithFS(t *testing.T) {
	memFS := fstest.MapFS{
		"templates/test.yaml": &fstest.MapFile{Data: []byte("id: test")},
	}

	catalog := NewFSCatalog(memFS, "templates")
	resolved, err := catalog.ResolvePath("templates/test.yaml", "")
	require.NoError(t, err)
	require.Equal(t, "templates/test.yaml", resolved)
}

func TestFindDirectoryMatchesWithFS(t *testing.T) {
	memFS := fstest.MapFS{
		"cves/cve-1.yaml": &fstest.MapFile{Data: []byte("id: cve-1")},
		"cves/cve-2.yaml": &fstest.MapFile{Data: []byte("id: cve-2")},
		"cves/readme.md":  &fstest.MapFile{Data: []byte("# readme")},
	}

	catalog := NewFSCatalog(memFS, "")
	paths, err := catalog.GetTemplatePath("cves")
	require.NoError(t, err)
	require.Len(t, paths, 2)
}

func TestFindDirectoryMatchesWithDisk(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "cves")
	err := os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	for _, name := range []string{"cve-1.yaml", "cve-2.yaml"} {
		err := os.WriteFile(filepath.Join(subDir, name), []byte("id: "+name), 0644)
		require.NoError(t, err)
	}
	// non-template file should be ignored
	err = os.WriteFile(filepath.Join(subDir, "readme.md"), []byte("# readme"), 0644)
	require.NoError(t, err)

	catalog := &DiskCatalog{templatesDirectory: tmpDir}
	paths, err := catalog.GetTemplatePath(subDir)
	require.NoError(t, err)
	require.Len(t, paths, 2)
}

func TestGetTemplatesPathSkipsKnownConfigFiles(t *testing.T) {
	memFS := fstest.MapFS{
		"cves.json":  &fstest.MapFile{Data: []byte("{}")},
		"test.yaml":  &fstest.MapFile{Data: []byte("id: test")},
	}

	catalog := NewFSCatalog(memFS, "")
	paths, _ := catalog.GetTemplatesPath([]string{"cves.json", "test.yaml"})
	for _, p := range paths {
		require.NotContains(t, p, "cves.json")
	}
}

func TestTryResolveWithFS(t *testing.T) {
	memFS := fstest.MapFS{
		"found.yaml": &fstest.MapFile{Data: []byte("id: found")},
	}

	catalog := NewFSCatalog(memFS, "")

	path, err := catalog.tryResolve("found.yaml")
	require.NoError(t, err)
	require.Equal(t, "found.yaml", path)

	_, err = catalog.tryResolve("notfound.yaml")
	require.ErrorIs(t, err, errNoValidCombination)
}

func TestFindFileMatchesWithFS(t *testing.T) {
	memFS := fstest.MapFS{
		"template.yaml": &fstest.MapFile{
			Data: []byte("id: test"),
			Mode: fs.ModePerm,
		},
	}

	catalog := NewFSCatalog(memFS, "")
	match, isFile, err := catalog.findFileMatches("template.yaml", make(map[string]struct{}))
	require.NoError(t, err)
	require.True(t, isFile)
	require.Equal(t, "template.yaml", match)
}
