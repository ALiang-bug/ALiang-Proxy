package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	dialogOK  = 1
	dialogYes = 6
)

func message(text string, flags uint32) int32 {
	body, _ := windows.UTF16PtrFromString(text)
	title, _ := windows.UTF16PtrFromString("ALiang Proxy Setup")
	answer, _ := windows.MessageBox(0, body, title, flags)
	return answer
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--verify-payload" {
		if err := verifyPayload(); err != nil {
			os.Exit(1)
		}
		return
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		message("Windows could not locate your local app data folder.", windows.MB_OK|windows.MB_ICONERROR)
		return
	}
	root := filepath.Join(base, "ALiangProxy", "Apps")
	if message("Install for your Windows account in:\r\n"+root, windows.MB_OKCANCEL) != dialogOK {
		return
	}
	executable, err := install(root, payload)
	if err != nil {
		message("Installation failed. Check free space and folder access.", windows.MB_OK|windows.MB_ICONERROR)
		return
	}
	status := "Open it later from Start by searching for ALiang Proxy Preview."
	if err := addStartMenuShortcut(executable); err != nil {
		status = "The Start menu shortcut could not be created. Use the executable path above."
	}
	if message("Installed at:\r\n"+executable+"\r\n\r\n"+status+"\r\n\r\nOpen ALiang Proxy now?", windows.MB_YESNO) == dialogYes {
		if err := exec.Command(executable).Start(); err != nil {
			message("Windows could not open the installed app. Try opening the executable from File Explorer.", windows.MB_OK|windows.MB_ICONERROR)
		}
	}
}

// Exercise extraction and shortcut creation without changing installed apps.
func verifyPayload() error {
	root, err := os.MkdirTemp("", "aliang-setup-test-")
	if err != nil {
		return err
	}
	executable, installErr := install(root, payload)
	if installErr == nil {
		installErr = writeShortcut(filepath.Join(root, "verification.lnk"), executable)
	}
	cleanupErr := os.RemoveAll(root)
	if installErr != nil {
		return installErr
	}
	return cleanupErr
}
