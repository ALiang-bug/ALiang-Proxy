package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"errors"
	"io"
	"os"
	"path/filepath"
)

//go:embed payload.zip
var payload []byte

func install(root string, data []byte) (string, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	allowed := map[string]bool{
		"ALiang-Proxy.exe": true, "proxy-core.exe": true,
		"ALiang-Proxy.ps1": true, "SystemProxy.ps1": true, "NodeTests.ps1": true,
		"Test-Core.ps1": true, "Test-SystemProxy.ps1": true, "Test-Tunnel.ps1": true,
		"Test-Offline.ps1": true, "README.md": true,
		"LICENSE-sing-box.txt": true, "LICENSE-gVisor.txt": true,
	}
	if len(archive.File) != len(allowed) {
		return "", errors.New("unexpected installer payload")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(root, "preview-")
	if err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(directory)
		}
	}()
	for _, entry := range archive.File {
		if !allowed[entry.Name] || !entry.Mode().IsRegular() || entry.UncompressedSize64 > 64<<20 {
			return "", errors.New("invalid installer entry")
		}
		delete(allowed, entry.Name)
		if err := extract(directory, entry); err != nil {
			return "", err
		}
	}
	complete = true
	return filepath.Join(directory, "ALiang-Proxy.exe"), nil
}

func extract(directory string, entry *zip.File) error {
	source, err := entry.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(filepath.Join(directory, entry.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(target, io.LimitReader(source, int64(entry.UncompressedSize64)+1))
	closeErr := target.Close()
	if copyErr != nil {
		return copyErr
	}
	if n != int64(entry.UncompressedSize64) {
		return errors.New("installer entry size mismatch")
	}
	return closeErr
}
