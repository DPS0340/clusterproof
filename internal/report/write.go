package report

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteNew atomically creates a private report and refuses an existing path.
func WriteNew(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".clusterproof-*")
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set report permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary report: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary report: %w", err)
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("create report %q without overwrite: %w", path, err)
	}
	return nil
}
