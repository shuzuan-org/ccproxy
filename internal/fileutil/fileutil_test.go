package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFile_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"hello":"world"}`)

	if err := AtomicWriteFile(path, data, 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 600", info.Mode().Perm())
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file in dir, got %d", len(entries))
	}
}

func TestAtomicWriteFile_Overwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")

	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("content = %q, want new", got)
	}
}

func TestAtomicWriteFile_InvalidDir(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nonexistent", "subdir", "file.txt")
	err := AtomicWriteFile(path, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestAtomicWriteFile_Permissions(t *testing.T) {
	t.Parallel()
	cases := []os.FileMode{0o644, 0o600, 0o400}
	for _, perm := range cases {
		t.Run(perm.String(), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "file.txt")
			if err := AtomicWriteFile(path, []byte("x"), perm); err != nil {
				t.Fatalf("AtomicWriteFile: %v", err)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != perm {
				t.Errorf("perm = %o, want %o", info.Mode().Perm(), perm)
			}
		})
	}
}

func TestAtomicWriteFile_EmptyData(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := AtomicWriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	if len(got) != 0 {
		t.Errorf("expected empty file, got %d bytes", len(got))
	}
}
