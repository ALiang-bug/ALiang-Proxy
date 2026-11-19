# ALiang Proxy for Windows

Windows 10/11 x64 development preview. Extract the complete ZIP into one folder and double-click `ALiang-Proxy.exe` under your normal account. The launcher uses the operating system's Windows PowerShell 5.1 and Windows Forms. If script execution is restricted, follow your organization's policy.

The bundle includes the sing-box license in `LICENSE-sing-box.txt`. The Windows x64 core embeds Wintun through its pinned sing-tun dependency. TUN uses a bundled worker and does not need a separate helper installation or DLL download. Windows administrator approval is required on each start so the core can configure the adapter and routes.

Import a local Clash YAML file or paste an HTTPS Clash YAML subscription into the masked field. Choose a VLESS/Trojan node or selector, then start the proxy. Set an application's HTTP or SOCKS5 proxy to `127.0.0.1:17890` to use it. Remove that application setting when you finish. The dashboard reports whether the local listener started. Remote reachability must be confirmed separately.

Stop the proxy before updating a subscription. The downloader uses normal TLS verification, no redirects, an eight-second deadline and a 1 MiB limit. A failed download or validation preserves the current profile. YAML and subscription addresses are stored with Windows DPAPI for the current user. The Go process receives requests over stdin, listens only on loopback and exits when the parent closes stdin.

**Node DNS** applies to node domain resolution for the next connection or batch test. Choose System DNS, AliDNS or Cloudflare. TUN uses the chosen option for node addresses on the underlying network. DNS queries received by the tunnel use the selected exit and the selected DoH service, or Cloudflare DoH when Node DNS is set to System DNS.

After starting the local proxy, click **Enable Windows proxy** to apply the loopback address for the current user. An existing enabled manual or script proxy prevents takeover. **Restore Windows proxy** restores the captured settings. Stopping the core, closing normally or reopening after a crash also attempts recovery. If another program changed the settings, check Windows Settings before attempting recovery again.

With the proxy stopped, **Batch node tests** checks individual nodes one at a time. Latency tests request an Apple HTTPS page. Download tests request a 5 MiB sample per node from Cloudflare. The dialog asks before each batch and supports cancellation. Successful results can be selected as the default exit by double-clicking.

Run `sh windows/build-core.sh` on the development Mac to verify the pinned sing-box archive, run the core tests and cross-compile the x64 core. The script reads the existing dependency pins and profile converter into a separate temporary tree. On Windows, `Test-SystemProxy.ps1` exercises apply, restore and external conflict handling with a temporary registry key. Native Windows acceptance, Wintun and production packaging are pending.

Run `sh windows/package-preview.sh` to rebuild both executables and create a clean portable ZIP with a SHA-256 checksum. The launcher is unsigned.

Run `.\Test-Core.ps1` from Windows PowerShell in an extracted or installed folder to check the included core. The smoke test validates a synthetic Trojan profile, checks a SOCKS5 greeting on loopback and verifies that EOF stops the core. It leaves system proxy and route settings untouched and does not connect to a remote node.

Run `.\Test-Offline.ps1` to check PowerShell syntax, run the core smoke test and verify proxy recovery against a temporary registry key in one pass. This does not exercise WinINet notifications, install a driver or start TUN.

Supply `-SetupPath 'C:\tests\ALiang-Proxy-Setup-x64.exe'` to also verify the matching installer on Windows. It extracts its embedded bundle, creates and reads back a shortcut in a temporary directory, then removes the directory. It leaves the Start menu and proxy settings unchanged.

The separately built `ALiang-Core-Tests-x64.exe` runs the Go core test suite natively without installing Go. In PowerShell, set `$env:ALIANG_TEST_LOOPBACK = '1'` before running `.\ALiang-Core-Tests-x64.exe -test.v` to include a synthetic Trojan TLS round trip through SOCKS5, port collision handling, and child process shutdown. These tests use loopback sockets and do not need a subscription.

The same command produces `ALiang-Proxy-Setup-x64.exe`, an unsigned per-user setup preview. It installs the bundled files in a new folder under `%LOCALAPPDATA%\ALiangProxy\Apps` and displays the exact launcher location. Search Start for **ALiang Proxy Preview** to reopen the latest installed copy. If Windows refuses shortcut creation, use the launcher path shown by Setup. To remove an installed copy, stop its proxy or tunnel, delete that copy's folder, and remove its shortcut if it still points there. The encrypted profile is stored separately and shared by copies under the same Windows account.

Use **Start TUN** in the app after selecting an exit, stopping the local proxy, restoring Windows proxy settings and closing other VPNs. Approve UAC as the same Windows account that saved the profile so the worker can decrypt it. The app stays open and reports when Windows selects the tunnel routes. **Stop TUN** and closing the app request graceful shutdown and compare the active default and split-default routes to their pre-TUN state. An unexpected app exit also requests cleanup through the worker's owner-process check. A recovery warning means the comparison or shutdown check failed. Packet forwarding and this lifecycle still require Windows validation.

Windows TUN uses Wintun with the gVisor userspace stack for packet forwarding. Once tunnel routes are active, **Check internet** asks for confirmation to resolve `www.apple.com` and request its HTTPS test page using normal Windows routes without an HTTP proxy. If the Windows DNS lookup fails, it queries the virtual IPv4 tunnel DNS server for the same hostname. Results contain no subscription details. The Windows lookup may use the DNS cache.

In a clean Windows test VM, an elevated Windows PowerShell can run:

```powershell
.\Test-Tunnel.ps1 -Profile 'C:\tests\test.yaml' -ExitNode 'test-node' -ApplyTunnel
```

This checks for existing proxy state and split-default routes, then checks the new interface and verifies that Windows selects it for one IPv4 and one IPv6 route lookup. Press Enter to close the core and compare default routes with the baseline. In a separate run in the test VM, add `-SimulateCrash` to terminate this run's core after route verification and compare the same baseline. The route lookups do not send test traffic. DNS and packet forwarding require separate tests.
