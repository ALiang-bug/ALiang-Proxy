package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallEmbeddedPayload(t *testing.T) {
	executable, err := install(t.TempDir(), payload)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range archive.File {
		source, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		want, err := io.ReadAll(source)
		_ = source.Close()
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(filepath.Dir(executable), entry.Name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("installed file differs: %s: %v", entry.Name, err)
		}
	}
}

func TestInstallRejectsUnexpectedPath(t *testing.T) {
	archive, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for i, entry := range archive.File {
		name := entry.Name
		if i == len(archive.File)-1 {
			name = "../outside"
		}
		if _, err := writer.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if _, err := install(root, data.Bytes()); err == nil {
		t.Fatal("unexpected entry was accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed installation left files: %v, %v", entries, err)
	}
}
