# thewatcher

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)]()

Fast, single-file async TCP port scanner for the terminal.
Zero third-party runtime dependencies. Python 3.9+ standard library only.
$ thewatcher -u example.com -1000
OPEN 22/tcp ssh [confirmed]
OPEN 80/tcp http [confirmed]
OPEN 443/tcp https [confirmed]

text

---

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

---

## Features

- **TCP connect scanning** — works as an unprivileged user, no `CAP_NET_RAW`.
- **Async concurrency** — 800 concurrent connections by default, tunable via `-c`.
- **Flexible port specs** — `-1000`, `-80 443`, `-1-1024`, `--ports 22,80,8000-8100`.
- **IPv4 and IPv6** — resolved via `getaddrinfo`.
- **Conservative service detection** — banner-based, with `confirmed` / `likely` / `guess` confidence.
- **Reports** — JSON, CSV, self-contained HTML.
- **Scan history** — save, list, show, remove. Never overwrites.
- **Diff** — compare two JSON reports (newly open, no longer open, service changed).
- **Defensive analysis** — rule-based, no vulnerability claims.
- **Proxy support** — SOCKS5 (with auth) and HTTP CONNECT.
- **Politeness mode** — `-s` reduces rate and increases timeout to avoid bans.
- **User-Agent rotation** — `-change` rotates UA for HTTP probes and jitters timing.
- **Zero runtime deps** — nothing to install for the tool itself.

---

## Install

### Requirements

- Python **3.9+** (check with `python3 --version`)
- Linux, macOS, or Windows

### Method A — `setup.sh` (recommended, no sudo)

```bash
git clone https://github.com/your-user/thewatcher.git
cd thewatcher
chmod +x setup.sh
./setup.sh
setup.sh tries, in order:

pipx if installed (isolated env, cleanest)

symlink to ~/.local/bin/thewatcher otherwise

No privileges needed. Everything under $HOME.

Method B — pipx
bash
pipx install .
Method C — pip --user
bash
python3 -m pip install --user .
Method D — manual symlink
bash
chmod +x thewatcher.py
mkdir -p ~/.local/bin
ln -s "$(pwd)/thewatcher.py" ~/.local/bin/thewatcher
Make sure ~/.local/bin is on your PATH. Add to ~/.bashrc or ~/.zshrc:

bash
export PATH="$HOME/.local/bin:$PATH"
Then source ~/.bashrc (or open a new terminal).

Verify
bash
thewatcher --version
# thewatcher 3.0.0
Uninstall
bash
./setup.sh --uninstall
# or:
pipx uninstall thewatcher
python3 -m pip uninstall thewatcher
rm ~/.local/bin/thewatcher
Quick start
bash
# Scan first 1000 ports
thewatcher -u example.com -1000

# Specific ports only
thewatcher -u example.com -80 443 8080

# Explicit range
thewatcher -u example.com -1-1024

# Only open port numbers (pipe-friendly)
thewatcher -u example.com -1000 -hide

# Polite mode + User-Agent rotation (avoids rate limiting)
thewatcher -u example.com -1000 -s -change

# Through a SOCKS5 proxy
thewatcher -u example.com -1000 -p socks5://127.0.0.1:9050

# Report to JSON and history
thewatcher -u example.com -1000 --json report.json --save

# Compare two reports
thewatcher diff old.json report.json

# Browse saved reports
thewatcher history list
Port syntax
Form	Meaning
-1000	range 1..1000 (N ≥ 1000 → range)
-80	exactly port 80
-80 443	exactly ports 80 and 443
-22 80 443 8080	exactly ports 22, 80, 443, 8080
-1-1024	explicit range 1..1024
-1000-2000	explicit range 1000..2000
--ports 22,80,8000-8100	comma-separated mixed specs
--profile quick	25 common ports
--profile standard	ports 1–1000 + common DB/admin ports
Rule: in -N, if N ≥ 1000 it becomes a range 1..N. If N < 1000 it is a single port. For precision with larger numbers use -A-B.

Flags
Flag	Effect
-u, --url TARGET	target hostname, IP, or URL
--ports SPEC	comma-separated port specs
--profile {quick,standard,custom}	port set (default: custom)
-c, --concurrency N	max concurrent connections (default 800)
-t, --timeout S	per-connection timeout in seconds (default 2.0)
-p, --proxy URL	socks5://user:pass@host:port or http://host:port
-change, --change	rotate UA, shuffle port order, jitter timing
-s, --slow	polite mode: c=50, t≥3.0, jitter per connection
-hide, --hide	only print open port numbers to stdout
--no-service-detect	disable banner-based service detection
--tls-probe	force TLS probe on every open port (slower)
--no-color	disable ANSI colors
--json PATH	write JSON report (- for stdout)
--csv PATH	write CSV report (- for stdout)
--html PATH	write self-contained HTML report
--save	save to ~/.thewatcher/reports/
--reports-dir DIR	override save directory
--version	print version and exit
-h, --help	print help and exit
Profiles
Profile	Ports
quick	25 commonly exposed ports (SSH, HTTP, HTTPS, SMB, RDP, databases, …)
standard	ports 1..1000 plus common database, RDP, VNC, Redis, Elasticsearch, MongoDB
custom	user-provided via --ports
The effective scan scope is printed before the scan starts so you always
know what is being probed.

Output formats
Human-readable (default)
text
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
JSON (--json out.json)
json
{
  "tool": "thewatcher",
  "version": "3.0.0",
  "timestamp": "2026-01-01T12:00:00+00:00",
  "duration_seconds": 1.83,
  "target": {"host": "example.com", "resolved_ip": "93.184.216.34"},
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
    {"port": 22, "state": "open", "service": "ssh",
     "product": null, "version": null, "confidence": "confirmed",
     "banner": "SSH-2.0-OpenSSH_9.6", "notes": [], "error": null}
  ],
  "defensive": [
    {"port": 22, "service": "SSH",
     "observation": "administrative service reachable on 22/tcp",
     "recommendation": "restrict to trusted management networks; ...",
     "level": "review"}
  ],
  "errors": [],
  "warnings": ["TCP connect cannot distinguish filtered from ..."]
}
CSV (--csv out.csv)
Columns: port, state, service, product, version, confidence, banner, notes, error.
One row per port. Safe to open in Excel / LibreOffice / pandas.read_csv.

HTML (--html report.html)
Self-contained. No JS. Opens in any browser. Includes results table,
defensive notes, and limitations.

Piping
--json - and --csv - write to stdout with no ANSI, no banners,
no progress lines. Safe to pipe:

bash
thewatcher -u example.com -1000 --json - | jq '.summary'
thewatcher -u example.com -1000 --csv  - | column -s, -t
thewatcher -u example.com -1000 -hide | xargs -I{} echo "open: {}"
Service detection
Conservative, evidence-based. Only observed facts are marked confirmed.

Confidence	Meaning
confirmed	a matching banner was observed (HTTP/, SSH-, 220 ... FTP, +OK, * OK, or TLS handshake)
likely	port is a well-known service port but no banner was captured
guess	an HTTP probe timed out but the port is a common web port
Port-to-service hints live in a small static map (PORT_HINTS).

Banner probes read at most 512 bytes with a short timeout.

No exploit payloads. No authentication attempts.

Disable entirely with --no-service-detect.

History and diff
Reports saved with --save go to ~/.thewatcher/reports/, named
YYYYmmddTHHMMSS_host.json. Override with --reports-dir DIR or
$THEWATCHER_HOME.

bash
# Save a scan
thewatcher -u example.com -1000 --save

# List saved reports
thewatcher history list

# Show a specific report
thewatcher history show 20260101T120000

# Remove a specific report (needs -y)
thewatcher history rm 20260101T120000 -y

# Diff two reports
thewatcher diff old.json new.json
diff output:

text
newly open:
  + 443/tcp https
no longer open:
  - 8080/tcp http-proxy
service changed:
  ~ 22/tcp ssh -> ssh-v2
History never overwrites — files are timestamped on every save.

Exit codes
Code	Meaning
0	success
1	scan or runtime error
2	invalid arguments
130	interrupted (Ctrl+C)
Safe to use in scripts:

bash
if thewatcher -u example.com -80 -hide; then
    echo "port 80 is open"
fi
Limitations
Read these before relying on results.

TCP connect only. Each scanned port is a full TCP handshake.
This is visible in target logs. It is not stealth scanning.

filtered = timeout. TCP connect cannot distinguish a firewall drop
from packet loss. filtered is not a confirmed verdict.

unknown means a non-classifiable error: permission denied, proxy
failure, or an unexpected OS error. See the error field in reports.

No OS detection. No TTL analysis, no TCP/IP stack fingerprinting.

No vulnerability scanning. An open port is not a vulnerability.
The defensive section highlights services that deserve review — that is
not a CVE claim.

No stealth or evasion. -s and -change reduce traffic rate and vary
timing. They are politeness features, not evasion.

IPv6 is attempted via getaddrinfo; whichever address resolves first
is used.

Proxy mode — filtered / unknown states may reflect proxy failures
rather than target behavior.

Testing
Tests run only against loopback fixtures (asyncio.start_server on port 0).
No internet access. No public targets.

bash
python3 -m pip install --user pytest
python3 -m pytest -v tests/