package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func launch(verify bool) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	directory := filepath.Dir(executable)
	for _, name := range []string{"ALiang-Proxy.ps1", "SystemProxy.ps1", "NodeTests.ps1", "Test-Tunnel.ps1", "proxy-core.exe"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("Extract the entire ALiang Proxy ZIP into one folder before starting it.")
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	powershell := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx := context.Background()
	args := []string{"-NoProfile", "-STA", "-File", filepath.Join(directory, "ALiang-Proxy.ps1")}
	if verify {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		args = append(args, "-VerifyUI")
	}
	command := exec.CommandContext(ctx, powershell, args...)
	command.Dir = directory
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	if err := command.Run(); err != nil {
		return errors.New("Windows could not start the app. Check that Windows PowerShell is available and that your script execution policy permits the extracted files.")
	}
	return nil
}

func main() {
	verify := len(os.Args) == 2 && os.Args[1] == "--verify-ui"
	if err := launch(verify); err != nil {
		if verify {
			os.Exit(1)
		}
		message, _ := windows.UTF16PtrFromString(err.Error())
		title, _ := windows.UTF16PtrFromString("ALiang Proxy")
		_, _ = windows.MessageBox(0, message, title, windows.MB_OK|windows.MB_ICONERROR)
		os.Exit(1)
	}
}
