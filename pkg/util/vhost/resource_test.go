package vhost

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetNotFoundPageContentCaching(t *testing.T) {
	require := require.New(t)

	// Default fallback
	NotFoundPagePath = ""
	content := getNotFoundPageContent()
	require.Contains(string(content), "The page you requested was not found")

	// Custom 404 file
	tmpDir := t.TempDir()
	customPath := filepath.Join(tmpDir, "404.html")
	require.NoError(os.WriteFile(customPath, []byte("<h1>Custom 404</h1>"), 0o600))

	NotFoundPagePath = customPath
	defer func() { NotFoundPagePath = "" }()

	content1 := getNotFoundPageContent()
	require.Equal("<h1>Custom 404</h1>", string(content1))

	// Modify file on disk; cached content should be returned without reading disk
	require.NoError(os.WriteFile(customPath, []byte("<h1>Modified 404</h1>"), 0o600))
	content2 := getNotFoundPageContent()
	require.Equal("<h1>Custom 404</h1>", string(content2))
}
