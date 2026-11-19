package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

func addStartMenuShortcut(executable string) error {
	programs, err := windows.KnownFolderPath(windows.FOLDERID_Programs, 0)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(programs, "aliang-shortcut-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	temporary := filepath.Join(stage, "ALiang Proxy Preview.lnk")
	if err := writeShortcut(temporary, executable); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(programs, "ALiang Proxy Preview.lnk"))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING)
}

func writeShortcut(path, executable string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
		// S_FALSE means the thread was already initialized in this mode.
		if status, ok := err.(*ole.OleError); !ok || status.Code() != 1 {
			return err
		}
	}
	defer ole.CoUninitialize()
	object, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return err
	}
	defer object.Release()
	shell, err := object.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer shell.Release()
	value, err := oleutil.CallMethod(shell, "CreateShortcut", path)
	if err != nil {
		return err
	}
	defer value.Clear()
	link := value.ToIDispatch()
	if link == nil {
		return errors.New("shell did not return a shortcut object")
	}
	for name, data := range map[string]string{
		"TargetPath": executable, "WorkingDirectory": filepath.Dir(executable),
		"Description": "ALiang Proxy Preview",
	} {
		result, err := oleutil.PutProperty(link, name, data)
		if err != nil {
			return err
		}
		_ = result.Clear()
	}
	result, err := oleutil.CallMethod(link, "Save")
	if err != nil {
		return err
	}
	if err := result.Clear(); err != nil {
		return err
	}
	stored, err := oleutil.CallMethod(shell, "CreateShortcut", path)
	if err != nil {
		return err
	}
	defer stored.Clear()
	dispatch := stored.ToIDispatch()
	if dispatch == nil {
		return errors.New("could not read saved shortcut")
	}
	target, err := oleutil.GetProperty(dispatch, "TargetPath")
	if err != nil {
		return err
	}
	defer target.Clear()
	if !strings.EqualFold(filepath.Clean(target.ToString()), filepath.Clean(executable)) {
		return errors.New("saved shortcut target differs from launcher path")
	}
	return nil
}
