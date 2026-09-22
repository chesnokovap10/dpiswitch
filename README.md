# DPI Switch

An AmneziaWG client for Windows built on the [mihomo](https://github.com/MetaCubeX/mihomo) core.
All traffic goes through the tunnel by default, while a detector checks in parallel whether
the ISP interferes with the direct path to each site. Sites that are not blocked are switched
to a direct connection and remembered.

Version: **1.0.2**

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

The result is `dist\dpiswitch.exe`. `mihomo.exe` must sit next to it; build a slim one with

```powershell
.\tools\build-mihomo.ps1
```

It pins the tested mihomo commit and drops what DPI Switch does not use (embedded
Tailscale, ZeroTier, EasyTier, Hysteria fake-TCP, debug symbols): ~39 MB instead of ~80 MB.
The release archive contains both binaries.

## Installation

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
