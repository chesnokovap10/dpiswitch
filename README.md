# DPI Switch

An AmneziaWG client for Windows built on the [mihomo](https://github.com/MetaCubeX/mihomo) core.
All traffic goes through the tunnel by default, while a detector checks in parallel whether
the ISP interferes with the direct path to each site. Sites that are not blocked are switched
to a direct connection and remembered.

Version: **1.0.8**

## Routing

Rules are evaluated top to bottom:

1. tunnel endpoints and local networks — direct;
2. excluded programs (`qbittorrent.exe`, etc.) — direct;
3. second-tunnel presets (YouTube, Telegram, AI services) and the custom list — **awg2**;
4. "always via tunnel" — **awg**;
5. "always direct" — direct;
6. detector verdicts — direct;
7. everything else — **awg**.

Fallback groups: if `awg2` is down, its traffic goes through `awg`; if both are down — direct.

## Detector

- candidates are taken from the core's live connections;
- a probe compares the direct path and the tunnel on **the same** node:
  TCP, TLS (certificate chain verification), HTTP, QUIC;
- verdicts: `CLEAN`, `BLOCKED_TCP/TLS/QUIC`, `MITM`, `CONTENT_DIFF`, `SLOWER`, `INCONCLUSIVE`;
- "clean" only if every attempt is clean: a false "clean" breaks a site,
  a false "blocked" only costs a detour through the tunnel;
- a verdict other than `CLEAN` is re-checked after an hour; each check in a row
  that finds the same doubles the wait, up to a day. A `CLEAN` found slower
  once is measured again before it is reverted;
- probes pause for a cycle after sleep and while the tunnel fails the core's
  own health checks: measurements then say more about the moment than the path;
- verdict memory is keyed by the ISP (ASN), not by the Wi-Fi network;
- "whole domains": 3+ clean subdomains and no bad ones — new subdomains go
  direct right away and are verified afterwards.

## DNS

- direct sites — Yandex DoH/DoT, queried outside the tunnel
  (CDNs return nodes for the user's ISP);
- tunnelled sites — the DNS inside the tunnel (from the `.conf`);
- applications receive fake addresses (fake-ip): IPv4 `198.18.0.0/16`,
  IPv6 `2001:2::/48`. The IPv6 range is deliberately not ULA: Chrome treats
  `fc00::/7` as a local network and blocks requests to it (Local Network Access).

## Build

Requires Go 1.26+.

```powershell
.\build.ps1
```

The result is a single `dist\dpiswitch.exe` with the mihomo core embedded inside
(gzip-compressed, ~24 MB in total). On the first build the core is built by
`tools\build-mihomo.ps1` into `dist\mihomo.exe` and reused afterwards; it pins the
tested mihomo commit and drops what DPI Switch does not use (embedded Tailscale,
ZeroTier, EasyTier, Hysteria fake-TCP, debug symbols): ~39 MB instead of ~80 MB.

At startup the service extracts the core to `%ProgramData%\dpiswitch\core\mihomo.exe`
and verifies its SHA-256 before every start, re-extracting it if it does not match.
That directory is writable by SYSTEM and Administrators only.

For development, `.\build.ps1 -NoEmbed` builds without the core; then `mihomo.exe`
must sit next to `dpiswitch.exe`.

`.\build.ps1 -Race` makes a debug build with the Go race detector into
`dist\dpiswitch-race.exe`, version `<version>-race`, symbols kept; it also runs the
tests under the detector. It needs cgo and gcc (`winget install
BrechtSanders.WinLibs.POSIX.UCRT`). The service sends its stderr, where race reports
go, to `%ProgramData%\dpiswitch\logs\service.log`. Expect it to be several times
slower and hungrier than the release build.

`.\tools\deploy.ps1` (`-Race` for the debug build, `-Path <exe>` for any other)
replaces the installed binary: it closes the tray, stops the service and waits
for it, copies with retries, starts both again and checks the hash. The
replaced binary is kept beside it as `dpiswitch.last.exe` — `-Path` with it
is the way back. No elevation is needed.

CI (GitHub Actions, `.github/workflows/ci.yml`) is kept within the free minutes:
a push to `main` that changes Go code runs `go vet` and the tests. The race
tests run by hand (`gh workflow run CI`); run on a `v*` tag
(`gh workflow run CI --ref vX.Y.Z`) it also checks the tag against
`version.go`, builds and attaches the zip and `SHA256SUMS.txt` to a draft
release.

## Installation

`dpiswitch.exe` is self-contained: there is nothing else to copy.

1. Run `dpiswitch.exe` — a tray icon appears.
2. Left click the icon — web UI; right click — menu.
3. "Install service" (one administrator prompt).
4. Load the AmneziaWG `.conf`; optionally a second `.conf` for awg2.

Data: `%ProgramData%\dpiswitch` (config, lists, verdicts, settings, logs).
Files containing private keys are locked down from other users.

## Commands

```
dpiswitch            tray (default)
dpiswitch install    install the service
dpiswitch uninstall  remove the service
dpiswitch reinstall  reinstall the service
dpiswitch version    show the version
```
