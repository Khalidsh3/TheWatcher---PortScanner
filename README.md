# thewatcher

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)]()

Fast, single-file asynchronous TCP port scanner for the terminal.

- Python 3.9+ standard library only
- No third-party runtime dependencies
- JSON, CSV, and HTML reports
- Scan history and report diffing

```text
$ thewatcher -u example.com -1000
OPEN 22/tcp ssh [confirmed]
OPEN 80/tcp http [confirmed]
OPEN 443/tcp https [confirmed]
```

## Table of contents

- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Port syntax](#port-syntax)
- [Flags](#flags)
- [Profiles](#profiles)
- [Output formats](#output-formats)
- [Service detection](#service-detection)
- [History and diff](#history-and-diff)
- [Exit codes](#exit-codes)
- [Limitations](#limitations)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Ethical use](#ethical-use)
- [License](#license)

## Features

- **TCP connect scanning** — works as an unprivileged user; no `CAP_NET_RAW` required.
- **Async concurrency** — 800 concurrent connections by default, tunable with `-c`.
- **Flexible port specifications** — supports `-1000`, `-80 443`, `-1-1024`, and `--ports 22,80,8000-8100`.
- **IPv4 and IPv6** — resolved through `getaddrinfo`.
- **Conservative service detection** — banner-based confidence levels: `confirmed`, `likely`, and `guess`.
- **Reports** — JSON, CSV, and self-contained HTML.
- **Scan history** — save, list, show, and remove reports without overwriting existing files.
- **Diff** — compare reports to find newly open ports, closed ports, and service changes.
- **Defensive analysis** — rule-based observations without vulnerability claims.
- **Proxy support** — SOCKS5 with authentication and HTTP CONNECT.
- **Politeness mode** — reduces rate and increases timeout to avoid unnecessary load.
- **User-Agent rotation** — rotates HTTP probe User-Agents and jitters timing.
- **Zero runtime dependencies** — nothing extra is required to run the tool.

## Install

### Requirements

- Python **3.9+**
- Linux, macOS, or Windows

Check your Python version:

```bash
python3 --version
```

### Method A — `setup.sh` (recommended)

```bash
git clone https://github.com/your-user/thewatcher.git
cd thewatcher
chmod +x setup.sh
./setup.sh
```

`setup.sh` tries the following, in order:

1. `pipx`, if installed
2. A symlink under `~/.local/bin`

No administrator privileges are required. Everything is installed under your home directory.

### Method B — pipx

```bash
pipx install .
```

### Method C — pip user install

```bash
python3 -m pip install --user .
```

### Method D — manual symlink

```bash
chmod +x thewatcher.py
mkdir -p ~/.local/bin
ln -s "$(pwd)/thewatcher.py" ~/.local/bin/thewatcher
```

Make sure `~/.local/bin` is on your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell or open a new terminal.

### Verify

```bash
thewatcher --version
# thewatcher 3.0.0
```

### Uninstall

```bash
./setup.sh --uninstall

# Or:
pipx uninstall thewatcher
python3 -m pip uninstall thewatcher
rm ~/.local/bin/thewatcher
```

## Quick start

```bash
# Scan the first 1000 ports
thewatcher -u example.com -1000

# Scan specific ports
thewatcher -u example.com -80 443 8080

# Scan an explicit range
thewatcher -u example.com -1-1024

# Print only open port numbers
thewatcher -u example.com -1000 -hide

# Polite mode with User-Agent rotation
thewatcher -u example.com -1000 -s -change

# Use a SOCKS5 proxy
thewatcher -u example.com -1000 -p socks5://127.0.0.1:9050

# Write a JSON report and save it to history
thewatcher -u example.com -1000 --json report.json --save

# Compare two reports
thewatcher diff old.json report.json

# Browse saved reports
thewatcher history list
```

## Port syntax

| Syntax | Meaning |
|---|---|
| `-1000` | Range `1..1000` because `N >= 1000` |
| `-80` | Port 80 only |
| `-80 443` | Ports 80 and 443 only |
| `-22 80 443 8080` | Ports 22, 80, 443, and 8080 |
| `-1-1024` | Explicit range `1..1024` |
| `-1000-2000` | Explicit range `1000..2000` |
| `--ports 22,80,8000-8100` | Comma-separated mixed specifications |
| `--profile quick` | Scan 25 common ports |
| `--profile standard` | Scan ports 1–1000 plus common database/admin ports |

> **Rule:** In `-N`, values where `N >= 1000` become the range `1..N`. Values below 1000 represent a single port. Use `-A-B` for an explicit range.

## Flags

| Flag | Effect |
|---|---|
| `-u`, `--url TARGET` | Target hostname, IP address, or URL |
| `--ports SPEC` | Comma-separated port specifications |
| `--profile {quick,standard,custom}` | Port set; default is `custom` |
| `-c`, `--concurrency N` | Maximum concurrent connections; default `800` |
| `-t`, `--timeout S` | Per-connection timeout; default `2.0` seconds |
| `-p`, `--proxy URL` | SOCKS5 or HTTP CONNECT proxy URL |
| `-change`, `--change` | Rotate User-Agent, shuffle ports, and jitter timing |
| `-s`, `--slow` | Polite mode: concurrency `50`, timeout at least `3.0` seconds |
| `-hide`, `--hide` | Print only open port numbers |
| `--no-service-detect` | Disable banner-based service detection |
| `--tls-probe` | Force a TLS probe on every open port |
| `--no-color` | Disable ANSI colors |
| `--json PATH` | Write a JSON report; use `-` for stdout |
| `--csv PATH` | Write a CSV report; use `-` for stdout |
| `--html PATH` | Write a self-contained HTML report |
| `--save` | Save to `~/.thewatcher/reports/` |
| `--reports-dir DIR` | Override the report directory |
| `--version` | Print the version and exit |
| `-h`, `--help` | Print help and exit |

## Profiles

| Profile | Ports |
|---|---|
| `quick` | 25 commonly exposed ports such as SSH, HTTP, HTTPS, SMB, RDP, and databases |
| `standard` | Ports `1..1000` plus common database, RDP, VNC, Redis, Elasticsearch, and MongoDB ports |
| `custom` | User-provided ports from `--ports` |

The effective scan scope is printed before scanning begins.

## Output formats

### Human-readable output

```text
target    : example.com
profile   : custom
ports     : 1000
threads   : 800
timeout   : 2.0s
service   : on

OPEN 22/tcp  ssh   [confirmed]
OPEN 80/tcp  http  [confirmed]
OPEN 443/tcp https [confirmed]

summary:
  duration  : 1.83s
  scanned   : 1000
  open      : 3
  closed    : 972
  filtered  : 25
  unknown   : 0
```

### JSON

```bash
thewatcher -u example.com -1000 --json out.json
```

Example:

```json
{
  "tool": "thewatcher",
  "version": "3.0.0",
  "timestamp": "2026-01-01T12:00:00+00:00",
  "duration_seconds": 1.83,
  "target": {
    "host": "example.com",
    "resolved_ip": "93.184.216.34"
  },
  "config": {
    "profile": "custom",
    "concurrency": 800,
    "timeout": 2.0,
    "service_detection": true,
    "proxy": null,
    "polite": false,
    "change_user_agent": false,
    "tls_probe": false
  },
  "summary": {
    "ports_scanned": 1000,
    "open": 3,
    "closed": 972,
    "filtered": 25,
    "unknown": 0
  },
  "results": [
    {
      "port": 22,
      "state": "open",
      "service": "ssh",
      "product": null,
      "version": null,
      "confidence": "confirmed",
      "banner": "SSH-2.0-OpenSSH_9.6",
      "notes": [],
      "error": null
    }
  ],
  "defensive": [],
  "errors": [],
  "warnings": [
    "TCP connect cannot distinguish filtered from packet loss"
  ]
}
```

### CSV

```bash
thewatcher -u example.com -1000 --csv out.csv
```

Columns:

```text
port, state, service, product, version, confidence, banner, notes, error
```

The file can be opened in Excel, LibreOffice, or loaded with `pandas.read_csv`.

### HTML

```bash
thewatcher -u example.com -1000 --html report.html
```

The generated report is self-contained, uses no JavaScript, and includes the results table, defensive notes, and limitations.

### Piping

`--json -` and `--csv -` write to stdout without ANSI colors, banners, or progress lines.

```bash
thewatcher -u example.com -1000 --json - | jq '.summary'
thewatcher -u example.com -1000 --csv - | column -s, -t
thewatcher -u example.com -1000 -hide | xargs -I{} echo "open: {}"
```

## Service detection

Service detection is conservative and evidence-based. Only observed facts are marked `confirmed`.

| Confidence | Meaning |
|---|---|
| `confirmed` | A matching banner was observed, such as `HTTP/`, `SSH-`, `220 ... FTP`, `+OK`, `* OK`, or a successful TLS handshake |
| `likely` | The port is commonly associated with a service, but no banner was captured |
| `guess` | An HTTP probe timed out, but the port is commonly used for web services |

Port-to-service hints live in a small static map named `PORT_HINTS`.

- Banner probes read at most 512 bytes with a short timeout.
- No exploit payloads are sent.
- No authentication attempts are made.
- Disable service detection with `--no-service-detect`.

## History and diff

Reports saved with `--save` are stored in `~/.thewatcher/reports/` using the format `YYYYmmddTHHMMSS_host.json`.

Use `--reports-dir DIR` or `$THEWATCHER_HOME` to customize the location.

```bash
# Save a scan
thewatcher -u example.com -1000 --save

# List saved reports
thewatcher history list

# Show a specific report
thewatcher history show 20260101T120000

# Remove a report; confirmation requires -y
thewatcher history rm 20260101T120000 -y

# Compare two reports
thewatcher diff old.json new.json
```

Example diff output:

```text
newly open:
  + 443/tcp https

no longer open:
  - 8080/tcp http-proxy

service changed:
  ~ 22/tcp ssh -> ssh-v2
```

History never overwrites existing reports; every save receives a timestamped filename.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success |
| `1` | Scan or runtime error |
| `2` | Invalid arguments |
| `130` | Interrupted with `Ctrl+C` |

Example:

```bash
if thewatcher -u example.com -80 -hide; then
    echo "port 80 is open"
fi
```

## Limitations

Read these limitations before relying on results:

- **TCP connect only:** every scanned port performs a full TCP handshake. This is visible in target logs and is not stealth scanning.
- **Filtered means timeout:** TCP connect scanning cannot distinguish a firewall drop from packet loss.
- **Unknown means an error:** examples include permission errors, proxy failures, and unexpected OS errors. See the report's `error` field.
- **No OS detection:** there is no TTL analysis or TCP/IP stack fingerprinting.
- **No vulnerability scanning:** an open port is not a vulnerability. Defensive notes are review recommendations, not CVE claims.
- **No stealth or evasion:** `-s` and `-change` reduce traffic rate and vary timing as politeness features.
- **IPv6 behavior:** `getaddrinfo` is used, and the first resolved address is selected.
- **Proxy behavior:** `filtered` and `unknown` may reflect proxy failures instead of target behavior.

## Testing

Tests run only against loopback fixtures using `asyncio.start_server` on port `0`. They do not access the internet or public targets.

```bash
python3 -m pip install --user pytest
python3 -m pytest -v tests/
```

## Project layout

```text
.
├── thewatcher.py
├── setup.sh
├── tests/
└── README.md
```

## Ethical use

Use this tool only on systems you own or are explicitly authorized to test. Respect network policies, rate limits, and applicable laws. Do not use it to bypass access controls, evade detection, or probe third-party systems without permission.

## License

This project is licensed under the [MIT License](LICENSE).
