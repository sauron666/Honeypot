# Installing MIRAGE

MIRAGE ships as a handful of static binaries with no runtime to install — no
database, no Docker, no Python, no .NET. Pick your platform and go.

## The fastest possible start (any OS)

Download the archive for your platform from the release page, unzip it, and run:

```
# Linux / macOS
./mirage-director --config profiles/p0-box.yaml

# Windows (PowerShell)
.\mirage-director.exe --config profiles\p0-box.yaml
```

Then open the operator console: **http://127.0.0.1:8422**

That starts the "honeypot in a box" profile — six decoy services on high ports,
no privileges needed. Attack it and watch the console light up:

```
curl http://127.0.0.1:8080/.env
ssh -p 2222 root@127.0.0.1      # password "toor" is accepted
```

Check the evidence chain is intact at any time:

```
./miragectl verify --file data/evidence.jsonl
```

## Building from source

Needs only Go 1.24+.

```
make build      # -> bin/mirage-director, miragectl, mirage-presence, mirage-breadcrumbs
make run        # build + start the P0 profile
make dist       # cross-compile release archives for every platform into dist/
```

`make dist` produces one zip per OS/arch (Linux, Windows, macOS; amd64 and
arm64). The binaries are CGO-free and statically linked, so a customer copies a
single file and runs it.

## Running it as a service

### Linux (systemd)

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mirage
sudo make install-systemd
sudo mkdir -p /etc/mirage
sudo cp profiles/p0-box.yaml /etc/mirage/config.yaml   # then edit it
sudo systemctl enable --now mirage-director
```

The unit (`packaging/mirage-director.service`) runs unprivileged and locked
down — a honeypot must never run as root. Evidence lives in
`/var/lib/mirage` and survives restarts.

### Windows (service)

From an elevated PowerShell, in the unzipped folder:

```
.\packaging\mirage-windows-service.ps1 -Install
```

This registers a Windows service via the built-in Service Control Manager (no
third-party tools), starts it, and writes a starter config to
`C:\ProgramData\MIRAGE\config.yaml`. The console is then at
http://127.0.0.1:8422.

Remove it with `-Uninstall`.

## Before production

Run the pre-flight check — it catches the mistakes you would otherwise find
during an incident:

```
miragectl doctor --config /path/to/config.yaml
```

It validates the config, checks driver coverage, verifies alert sinks are
reachable, and — for full-OS decoys — checks containment is actually enforced.
Fix anything it flags. The checklist in `profiles/README.md` covers the rest:
keep the management API off the decoy segment, set an API token if it is not on
loopback, and preserve `data_dir/deploy.seed` so decoys stay stable across
restarts.

## Choosing a profile

| Profile | For |
|---|---|
| `profiles/p0-box.yaml` | One process, six services. The ten-minute install. |
| `profiles/p3-mssp-overlay.yaml` | Decoys in a remote segment via a mutual-TLS overlay, no network change. |
| `profiles/p4-fullvm.yaml` | Full-OS VM decoys on a hypervisor, with verified containment. |
| `profiles/homelab-proxmox-opnsense.yaml` | A worked home-lab example. |

Copy one, edit it, point `--config` at it. `docs/06-DEPLOYMENT-PROFILES.md`
explains the trade-offs.
