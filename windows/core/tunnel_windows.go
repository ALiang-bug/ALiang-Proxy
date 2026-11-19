package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

func checkTunnelAccess() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("tunnel_requires_administrator")
	}
	return nil
}
