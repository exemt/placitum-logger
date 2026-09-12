package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestList(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "002_b.sql"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "001_a.sql"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	names, err := list(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(names) != 2 || names[0] != "001_a.sql" || names[1] != "002_b.sql" {
		t.Fatalf("order: %v", names)
	}
}
