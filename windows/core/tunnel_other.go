//go:build !windows

package main

import "errors"

func checkTunnelAccess() error { return errors.New("windows_tunnel_only") }
