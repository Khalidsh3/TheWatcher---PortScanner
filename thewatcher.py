#!/usr/bin/env python3
"""
thewatcher.py — async TCP connect port scanner. CLI only. By The Watcher.

Single-file, stdlib-only. No GUI, no TUI, no web.

Subcommands:
    scan      run a scan (default when a target is given without subcommand)
    diff      compare two JSON reports
    history   list / show / remove saved reports

Target specs (multi-target supported in v3.1.0):
    -u 1.2.3.4                         single IP
    -u example.com                     single hostname
    -u 1.2.3.4,5.6.7.8                 comma-separated
    -u 192.168.1.1-192.168.1.254       IPv4 range
    -u 192.168.1.0/24                  IPv4 CIDR
    -u http://1.2.3.4:8080             URL with explicit port

Backward-compatible short flags:
    -1000               expand 1..1000
    -80 443             scan exactly 80 and 443
    -1-1024             explicit range
    -hide               quiet (open ports only)
    -change             rotate User-Agent, shuffle order, jitter timing
    -s / -no_noise      polite / slow mode (lower rate, longer timeout)
    -p PROXY            socks5:// or http:// proxy

Exit codes:
    0    success
    1    scan or runtime error
    2    invalid arguments
    130  interrupted (Ctrl+C)
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import datetime
import html as html_mod
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "3.1.0"

DEFAULT_CONCURRENCY = 800
DEFAULT_TIMEOUT = 2.0

POLITE_CONCURRENCY = 50
POLITE_TIMEOUT = 3.0
POLITE_JITTER = (0.05, 0.30)

MIN_PORT = 1
MAX_PORT = 65535
RANGE_THRESHOLD = 1000
PORT_COUNT_WARN = 10000
MAX_TARGETS = 4096

EXIT_OK = 0
EXIT_ERR = 1
EXIT_ARGS = 2
EXIT_INTERRUPTED = 130

QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]

STANDARD_PORTS = list(range(1, 1001)) + [
    1433, 1521, 3306, 3389, 5432, 5900, 5984, 6379, 8000, 8080,
    8443, 8888, 9000, 9090, 9200, 27017, 50000, 50070,
]

PORT_HINTS: Dict[int, Tuple[str, str]] = {
    21: ("ftp", "file transfer (plaintext)"),
    22: ("ssh", "secure shell"),
    23: ("telnet", "remote login (plaintext)"),
    25: ("smtp", "mail submission"),
    53: ("dns", "domain name service"),
    80: ("http", "web (plaintext)"),
    110: ("pop3", "mail (plaintext)"),
    143: ("imap", "mail (plaintext)"),
    443: ("https", "web (tls)"),
    445: ("smb", "windows file sharing"),
    993: ("imaps", "mail (tls)"),
    995: ("pop3s", "mail (tls)"),
    1433: ("mssql", "microsoft sql server"),
    1521: ("oracle", "oracle database"),
    3306: ("mysql", "mysql database"),
    3389: ("rdp", "remote desktop"),
    5432: ("postgres", "postgresql database"),
    5900: ("vnc", "vnc remote desktop"),
    6379: ("redis", "redis cache"),
    8080: ("http-proxy", "web/proxy (plaintext)"),
    8443: ("https-alt", "web (tls)"),
    9200: ("elasticsearch", "elasticsearch"),
    27017: ("mongodb", "mongodb"),
}

ADMIN_SERVICES = {22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP"}
DB_SERVICES = {
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
}
CLEARTEXT_WEB_PORTS = {80, 8000, 8080, 8888}
TLS_PORTS = {443, 8443, 993, 995}
BANNER_GREETING_PORTS = {21, 22, 25, 110, 143, 587}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 "
    "Safari/604.1",
    "curl/8.4.0",
    "Wget/1.21.4",
    "python-requests/2.31.0",
]


# ===========================================================================
# terminal
# ===========================================================================
class Term:
    COLOR: bool = (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
    )

    @classmethod
    def disable(cls) -> None:
        cls.COLOR = False

    @classmethod
    def _c(cls, t: str, code: str) -> str:
        return f"\x1b[{code}m{t}\x1b[0m" if cls.COLOR else t

    @classmethod
    def green(cls, t: str) -> str:
        return cls._c(t, "32")

    @classmethod
    def red(cls, t: str) -> str:
        return cls._c(t, "31")

    @classmethod
    def yellow(cls, t: str) -> str:
        return cls._c(t, "33")

    @classmethod
    def cyan(cls, t: str) -> str:
        return cls._c(t, "36")

    @classmethod
    def dim(cls, t: str) -> str:
        return cls._c(t, "2")

    @classmethod
    def bold(cls, t: str) -> str:
        return cls._c(t, "1")


# ===========================================================================
# errors
# ===========================================================================
class ArgError(Exception):
    pass


# ===========================================================================
# port parsing
# ===========================================================================
def parse_port_token(tok: str) -> List[Tuple[int, int]]:
    tok = tok.strip()
    if not tok:
        return []
    if "-" in tok:
        a_s, b_s = tok.split("-", 1)
        try:
            a, b = int(a_s), int(b_s)
        except ValueError:
            raise ArgError(f"invalid port range: {tok}")
        if a > b:
            a, b = b, a
        if not (MIN_PORT <= a <= MAX_PORT and MIN_PORT <= b <= MAX_PORT):
            raise ArgError(f"port out of range: {tok}")
        return [(a, b)]
    try:
        n = int(tok)
    except ValueError:
        raise ArgError(f"invalid port: {tok}")
    if not (MIN_PORT <= n <= MAX_PORT):
        raise ArgError(f"port out of range: {tok}")
    return [(n, n)]


def parse_ports_spec(spec: str) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for tok in spec.split(","):
        tok = tok.strip()
        if tok:
            out.extend(parse_port_token(tok))
    return out


def expand_ports(specs: List[Tuple[int, int]]) -> List[int]:
    seen: set = set()
    out: List[int] = []
    for a, b in specs:
        for p in range(a, b + 1):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


# ===========================================================================
# targets
# ===========================================================================
def parse_target(target: str) -> str:
    t = target.strip()
    if not t:
        raise ArgError("empty target")
    if "://" not in t:
        t = "http://" + t
    try:
        u = urllib.parse.urlparse(t)
    except ValueError as e:
        raise ArgError(f"invalid target: {e}")
    host = u.hostname
    if not host:
        raise ArgError(f"invalid target: {target}")
    return host


def extract_url_port(target: str) -> Optional[int]:
    """If target is a URL with an explicit port, return it. Else None."""
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    try:
        u = urllib.parse.urlparse(t)
        return u.port
    except ValueError:
        return None


def _looks_like_ip_range(tok: str) -> bool:
    """True only when tok is 'A.B.C.D-E.F.G.H' with valid IPv4 on both sides."""
    if tok.count("-") != 1:
        return False
    a_s, b_s = tok.split("-", 1)
    try:
        ipaddress.IPv4Address(a_s.strip())
        ipaddress.IPv4Address(b_s.strip())
        return True
    except ValueError:
        return False


def expand_targets(spec: str) -> List[str]:
    """Expand a target spec into a list of hostnames/IPs.

    Supports:
      - single host or IP:       example.com, 1.2.3.4
      - comma-separated:         1.2.3.4,5.6.7.8,example.com
      - IPv4 range:              192.168.1.1-192.168.1.254
      - IPv4 CIDR:               192.168.1.0/24, 10.0.0.0/30
    """
    tokens = [t.strip() for t in spec.split(",") if t.strip()]
    if not tokens:
        raise ArgError("empty target spec")

    out: List[str] = []
    for tok in tokens:
        if "/" in tok:
            try:
                net = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                raise ArgError(f"invalid CIDR: {tok}")
            if net.version != 4:
                raise ArgError(
                    f"IPv6 CIDR not supported (use a hostname or a single "
                    f"IPv6 address): {tok}"
                )
            if net.num_addresses > MAX_TARGETS:
                raise ArgError(
                    f"CIDR too large: {tok} has {net.num_addresses} "
                    f"addresses > limit {MAX_TARGETS}"
                )
            if net.prefixlen >= 31:
                for ip in net:
                    out.append(str(ip))
            else:
                for ip in net.hosts():
                    out.append(str(ip))
        elif _looks_like_ip_range(tok):
            a_s, b_s = tok.split("-", 1)
            a = ipaddress.IPv4Address(a_s.strip())
            b = ipaddress.IPv4Address(b_s.strip())
            if int(a) > int(b):
                raise ArgError(f"reversed IP range: {tok}")
            count = int(b) - int(a) + 1
            if count > MAX_TARGETS:
                raise ArgError(
                    f"IP range too large: {tok} has {count} "
                    f"addresses > limit {MAX_TARGETS}"
                )
            for i in range(int(a), int(b) + 1):
                out.append(str(ipaddress.IPv4Address(i)))
        else:
            out.append(tok)

    if not out:
        raise ArgError("no targets after expansion")
    return out


async def resolve_host(host: str) -> Tuple[str, int]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        raise ArgError(f"cannot resolve {host}: {e}")
    if not infos:
        raise ArgError(f"no addresses for {host}")
    return infos[0][4][0], infos[0][0]


# ===========================================================================
# proxy
# ===========================================================================
@dataclass
class Proxy:
    scheme: str
    host: str
    port: int
    user: Optional[str] = None
    password: Optional[str] = None

    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def parse_proxy(p: str) -> Proxy:
    if "://" not in p:
        p = "socks5://" + p
    try:
        u = urllib.parse.urlparse(p)
    except ValueError as e:
        raise ArgError(f"invalid proxy: {e}")
    if u.scheme not in ("socks5", "socks5h", "http", "https"):
        raise ArgError(f"unsupported proxy scheme: {u.scheme}")
    if not u.hostname:
        raise ArgError(f"invalid proxy: {p}")
    default_port = 1080 if u.scheme.startswith("socks") else 8080
    return Proxy(
        scheme=u.scheme, host=u.hostname,
        port=u.port or default_port,
        user=u.username, password=u.password,
    )


async def _socks5_open(proxy: Proxy, host: str, port: int, timeout: float):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout=timeout
        )
    except Exception:
        return None
    try:
        methods = b"\x00\x02" if proxy.user else b"\x00"
        writer.write(b"\x05" + bytes([len(methods)]) + methods)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != 5:
            writer.close()
            return None
        if resp[1] == 0x02:
            if not proxy.user:
                writer.close()
                return None
            u = proxy.user.encode()
            pw = (proxy.password or "").encode()
            writer.write(
                b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw
            )
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            ar = await asyncio.wait_for(
                reader.readexactly(2), timeout=timeout
            )
            if ar[1] != 0:
                writer.close()
                return None
        elif resp[1] != 0:
            writer.close()
            return None
        hb = host.encode("idna") if host else b""
        if not hb or len(hb) > 255:
            writer.close()
            return None
        writer.write(
            b"\x05\x01\x00\x03"
            + bytes([len(hb)]) + hb
            + port.to_bytes(2, "big")
        )
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        reply = await asyncio.wait_for(
            reader.readexactly(4), timeout=timeout
        )
        if reply[1] != 0:
            writer.close()
            return None
        atyp = reply[3]
        if atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        elif atyp == 0x03:
            n = (await asyncio.wait_for(
                reader.readexactly(1), timeout=timeout
            ))[0]
            await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
        elif atyp == 0x04:
            await asyncio.wait_for(reader.readexactly(16), timeout=timeout)
        await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        return reader, writer
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        return None


async def _http_connect_open(
    proxy: Proxy, host: str, port: int, timeout: float
):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.host, proxy.port), timeout=timeout
        )
    except Exception:
        return None
    try:
        auth = ""
        if proxy.user:
            creds = base64.b64encode(
                f"{proxy.user}:{proxy.password or ''}".encode()
            ).decode()
            auth = f"Proxy-Authorization: Basic {creds}\r\n"
        req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n{auth}\r\n"
        ).encode()
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if b" 200 " not in line:
            writer.close()
            return None
        while True:
            h = await asyncio.wait_for(
                reader.readline(), timeout=timeout
            )
            if h in (b"\r\n", b"\n", b""):
                break
        return reader, writer
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        return None


async def proxy_open(proxy: Proxy, host: str, port: int, timeout: float):
    if proxy.scheme.startswith("socks"):
        return await _socks5_open(proxy, host, port, timeout)
    return await _http_connect_open(proxy, host, port, timeout)


# ===========================================================================
# port result
# ===========================================================================
@dataclass
class PortResult:
    port: int
    state: str
    error: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: Optional[str] = None
    notes: List[str] = field(default_factory=list)


# ===========================================================================
# service detection
# ===========================================================================
def _pick_ua(change_ua: bool) -> str:
    return random.choice(USER_AGENTS) if change_ua else USER_AGENTS[0]


async def _probe_tls(
    ip: str, host: str, port: int, timeout: float
) -> Optional[str]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ssl.SSLError, AttributeError):
        return None
    try:
        _r, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host),
            timeout=min(timeout, 3.0),
        )
        sslobj = writer.get_extra_info("ssl_object")
        ver = sslobj.version() if sslobj else None
        cipher = writer.get_extra_info("cipher")
        try:
            writer.close()
        except Exception:
            pass
        if ver:
            out = f"tls:{ver}"
            if cipher:
                out += f" cipher={cipher[0]}"
            return out
        return "tls"
    except Exception:
        return None


async def _http_banner(
    reader, writer, host: str, port: int, timeout: float, change_ua: bool
) -> Optional[str]:
    ua = _pick_ua(change_ua)
    req = (
        f"HEAD / HTTP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    writer.write(req)
    await asyncio.wait_for(writer.drain(), timeout=min(timeout, 2.0))
    data = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 2.0))
    return data.decode("utf-8", errors="replace").strip() if data else None


async def _greeting_banner(reader, timeout: float) -> Optional[str]:
    data = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 2.0))
    return data.decode("utf-8", errors="replace").strip() if data else None


def _classify_banner(
    port: int, banner: str
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    b = banner.lower()[:128]
    if b.startswith("http/") or " http/" in b:
        return "http", None, None, "confirmed"
    if b.startswith("ssh-"):
        return "ssh", None, None, "confirmed"
    if b.startswith("220") and "ftp" in b:
        return "ftp", None, None, "confirmed"
    if b.startswith("220") and ("smtp" in b or "esmtp" in b):
        return "smtp", None, None, "confirmed"
    if b.startswith("+ok"):
        return "pop3", None, None, "confirmed"
    if b.startswith("* ok"):
        return "imap", None, None, "confirmed"
    return None, None, None, None


# ===========================================================================
# scan port
# ===========================================================================
async def scan_port(
    ip: str,
    host: str,
    port: int,
    proxy: Optional[Proxy],
    timeout: float,
    detect_service: bool,
    change_ua: bool,
    force_tls: bool,
) -> PortResult:
    try:
        if proxy:
            r = await proxy_open(proxy, host, port, timeout)
            if r is None:
                return PortResult(
                    port=port, state="unknown", error="proxy_failure"
                )
        else:
            r = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
    except asyncio.TimeoutError:
        return PortResult(port=port, state="filtered")
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed")
    except PermissionError:
        return PortResult(
            port=port, state="unknown", error="permission_denied"
        )
    except OSError as e:
        return PortResult(
            port=port, state="unknown", error=f"{type(e).__name__}: {e}"
        )
    except Exception as e:
        return PortResult(
            port=port, state="unknown", error=f"{type(e).__name__}: {e}"
        )

    reader, writer = r
    result = PortResult(port=port, state="open")
    hint = PORT_HINTS.get(port)

    if detect_service:
        try:
            tls_done = False
            if force_tls and not proxy:
                tls_info = await _probe_tls(ip, host, port, timeout)
                if tls_info:
                    result.banner = tls_info[:200]
                    result.service = hint[0] if hint else "tls"
                    result.confidence = "confirmed"
                    tls_done = True
                elif hint:
                    result.service = hint[0]
                    result.confidence = "likely"
                    tls_done = True

            if not tls_done and not proxy and port in TLS_PORTS:
                tls_info = await _probe_tls(ip, host, port, timeout)
                if tls_info:
                    result.banner = tls_info[:200]
                    result.service = hint[0] if hint else "tls"
                    result.confidence = "confirmed"
                    tls_done = True
                elif hint:
                    result.service = hint[0]
                    result.confidence = "likely"
                    tls_done = True

            if not tls_done and port in CLEARTEXT_WEB_PORTS:
                banner = await _http_banner(
                    reader, writer, host, port, timeout, change_ua
                )
                if banner:
                    result.banner = banner[:200]
                    svc, prod, ver, conf = _classify_banner(port, banner)
                    if svc:
                        result.service = svc
                    if prod:
                        result.product = prod
                    if ver:
                        result.version = ver
                    if conf:
                        result.confidence = conf
                elif hint:
                    result.service = hint[0]
                    result.confidence = "guess"

            if (
                not tls_done
                and not result.service
                and port in BANNER_GREETING_PORTS
            ):
                banner = await _greeting_banner(reader, timeout)
                if banner:
                    result.banner = banner[:200]
                    svc, prod, ver, conf = _classify_banner(port, banner)
                    if svc:
                        result.service = svc
                    if prod:
                        result.product = prod
                    if ver:
                        result.version = ver
                    if conf:
                        result.confidence = conf
                elif hint:
                    result.service = hint[0]
                    result.confidence = "guess"

            if not result.service and hint:
                result.service = hint[0]
                result.confidence = "likely"

        except Exception as e:
            result.notes.append(
                f"service_check_failed:{type(e).__name__}"
            )
            if hint and not result.service:
                result.service = hint[0]
                result.confidence = "guess"

    try:
        writer.close()
    except Exception:
        pass
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
    except Exception:
        pass
    return result


# ===========================================================================
# scan orchestrators
# ===========================================================================
async def scan_target_single(
    target: str,
    ports: List[int],
    timeout: float,
    concurrency: int,
    proxy: Optional[Proxy],
    detect_service: bool,
    change_ua: bool,
    polite: bool,
    force_tls: bool,
    on_result: Callable[[PortResult, int, int], None],
    results_out: List[PortResult],
    errors_out: List[str],
) -> Tuple[str, str, float]:
    host = parse_target(target)
    ip, _family = await resolve_host(host)

    queue: asyncio.Queue = asyncio.Queue()
    for p in ports:
        queue.put_nowait(p)

    total = len(ports)
    done = 0
    lock = asyncio.Lock()
    stop = asyncio.Event()

    async def worker() -> None:
        nonlocal done
        while not stop.is_set():
            try:
                p = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                res = await scan_port(
                    ip, host, p, proxy, timeout, detect_service,
                    change_ua, force_tls,
                )
                async with lock:
                    results_out.append(res)
                    done += 1
                    on_result(res, done, total)
                if polite:
                    await asyncio.sleep(random.uniform(*POLITE_JITTER))
            except asyncio.CancelledError:
                raise
            except Exception as e:
                async with lock:
                    errors_out.append(
                        f"port {p}: {type(e).__name__}: {e}"
                    )
                    done += 1

    started = time.time()
    workers = [
        asyncio.create_task(worker())
        for _ in range(max(1, min(concurrency, total)))
    ]
    try:
        await asyncio.gather(*workers, return_exceptions=True)
    except asyncio.CancelledError:
        stop.set()
        for w in workers:
            if not w.done():
                w.cancel()
        raise
    finally:
        for w in workers:
            if not w.done():
                w.cancel()
    elapsed = time.time() - started
    results_out.sort(key=lambda r: r.port)
    return host, ip, elapsed


async def scan_targets(
    targets: List[str],
    ports: List[int],
    timeout: float,
    concurrency: int,
    proxy: Optional[Proxy],
    detect_service: bool,
    change_ua: bool,
    polite: bool,
    force_tls: bool,
    on_target_start: Callable[[str, int, int], None],
    on_result: Callable[[str, PortResult, int, int], None],
    on_target_done: Callable[[str, str, float], None],
    scans_out: List[Tuple[str, str, List[PortResult], float]],
    errors_out: List[str],
) -> float:
    """Scan multiple targets sequentially. Each target is scanned with its
    own bounded worker pool. Aggregates errors, preserves per-target results."""
    overall_started = time.time()
    for idx, target in enumerate(targets, 1):
        on_target_start(target, idx, len(targets))
        per_results: List[PortResult] = []
        per_errors: List[str] = []
        try:
            host, ip, elapsed = await scan_target_single(
                target, ports, timeout, concurrency, proxy,
                detect_service, change_ua, polite, force_tls,
                lambda r, d, t: on_result(target, r, d, t),
                per_results, per_errors,
            )
            scans_out.append((target, ip, per_results, elapsed))
            on_target_done(target, ip, elapsed)
            for e in per_errors:
                errors_out.append(f"{target}: {e}")
        except ArgError as e:
            errors_out.append(f"{target}: {e}")
            on_target_done(target, "", 0.0)
        except Exception as e:
            errors_out.append(f"{target}: {type(e).__name__}: {e}")
            on_target_done(target, "", 0.0)
    return time.time() - overall_started


# ===========================================================================
# defensive analysis
# ===========================================================================
def defensive_analysis(results: List[PortResult]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in results:
        if r.state != "open":
            continue
        if r.port in DB_SERVICES:
            out.append({
                "port": r.port,
                "service": DB_SERVICES[r.port],
                "observation": (
                    f"database service reachable on {r.port}/tcp"
                ),
                "recommendation": (
                    "verify firewall rules and network ACLs; databases "
                    "typically should not be reachable from untrusted "
                    "networks"
                ),
                "level": "review",
            })
        elif r.port in ADMIN_SERVICES:
            out.append({
                "port": r.port,
                "service": ADMIN_SERVICES[r.port],
                "observation": (
                    f"administrative service reachable on {r.port}/tcp"
                ),
                "recommendation": (
                    "restrict to trusted management networks; verify "
                    "authentication strength and logging"
                ),
                "level": "review",
            })
        elif r.port == 23:
            out.append({
                "port": r.port,
                "service": "Telnet",
                "observation": "unencrypted remote-login protocol",
                "recommendation": (
                    "prefer SSH; Telnet transmits credentials in cleartext"
                ),
                "level": "review",
            })
        elif r.port in CLEARTEXT_WEB_PORTS:
            svc = (r.service or "").lower()
            if svc in ("http", "http-proxy", ""):
                out.append({
                    "port": r.port,
                    "service": "HTTP",
                    "observation": (
                        "web service reachable over plaintext HTTP"
                    ),
                    "recommendation": (
                        "consider HTTPS; verify the served content matches "
                        "expectations"
                    ),
                    "level": "info",
                })
    return out


# ===========================================================================
# report build
# ===========================================================================
def _result_to_dict(r: PortResult) -> Dict[str, Any]:
    return {
        "port": r.port,
        "state": r.state,
        "service": r.service,
        "product": r.product,
        "version": r.version,
        "confidence": r.confidence,
        "banner": r.banner,
        "notes": r.notes,
        "error": r.error,
    }


def _summarize(results: List[PortResult]) -> Dict[str, int]:
    return {
        "open": sum(1 for r in results if r.state == "open"),
        "closed": sum(1 for r in results if r.state == "closed"),
        "filtered": sum(1 for r in results if r.state == "filtered"),
        "unknown": sum(1 for r in results if r.state == "unknown"),
    }


def _aggregate_summary(
    scans: List[Tuple[str, str, List[PortResult], float]]
) -> Dict[str, int]:
    total = {"open": 0, "closed": 0, "filtered": 0, "unknown": 0}
    for _t, _ip, results, _e in scans:
        for state in total:
            total[state] += sum(1 for r in results if r.state == state)
    return total


def build_report(
    scans: List[Tuple[str, str, List[PortResult], float]],
    ports: List[int],
    elapsed: float,
    config: Dict[str, Any],
    errors: List[str],
    warnings: List[str],
) -> Dict[str, Any]:
    """scans: list of (target_spec, resolved_ip, results, per_target_elapsed)."""
    scan_entries: List[Dict[str, Any]] = []
    for target, ip, results, per_elapsed in scans:
        scan_entries.append({
            "target": {"host": target, "resolved_ip": ip},
            "duration_seconds": round(per_elapsed, 3),
            "summary": {**_summarize(results), "ports_scanned": len(ports)},
            "results": [_result_to_dict(r) for r in results],
            "defensive": defensive_analysis(results),
        })

    report: Dict[str, Any] = {
        "tool": "thewatcher",
        "version": VERSION,
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "duration_seconds": round(elapsed, 3),
        "config": config,
        "target_count": len(scans),
        "summary": {
            "targets": len(scans),
            "ports_scanned_per_target": len(ports),
            **_aggregate_summary(scans),
        },
        "scans": scan_entries,
        "errors": errors,
        "warnings": warnings,
    }

    if len(scans) == 1:
        s = scan_entries[0]
        report["target"] = s["target"]
        report["results"] = s["results"]
        report["defensive"] = s["defensive"]
        report["summary"]["ports_scanned"] = len(ports)

    return report


def _flatten_results(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flat results, each row annotated with target + target_ip."""
    rows: List[Dict[str, Any]] = []
    if report.get("target_count", 1) <= 1 and "results" in report:
        tgt = report.get("target", {}).get("host", "")
        ip = report.get("target", {}).get("resolved_ip", "")
        for r in report["results"]:
            row = dict(r)
            row["target"] = tgt
            row["target_ip"] = ip
            rows.append(row)
        return rows
    for scan in report.get("scans", []):
        tgt = scan["target"]["host"]
        ip = scan["target"]["resolved_ip"]
        for r in scan["results"]:
            row = dict(r)
            row["target"] = tgt
            row["target_ip"] = ip
            rows.append(row)
    return rows


# ===========================================================================
# report serialization
# ===========================================================================
def _atomic_write(path: Path, write_fn: Callable[[Path], None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    write_fn(tmp)
    os.replace(tmp, path)


def write_json(path: Path, report: Dict[str, Any]) -> None:
    def _w(p: Path) -> None:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    _atomic_write(path, _w)


def write_csv(path: Path, report: Dict[str, Any]) -> None:
    fields = [
        "target", "target_ip",
        "port", "state", "service", "product", "version",
        "confidence", "banner", "notes", "error",
    ]
    rows = _flatten_results(report)

    def _w(p: Path) -> None:
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(
                f, fieldnames=fields, extrasaction="ignore"
            )
            w.writeheader()
            for row in rows:
                row = dict(row)
                row["notes"] = ";".join(row.get("notes") or [])
                w.writerow(row)
    _atomic_write(path, _w)


def write_html(path: Path, report: Dict[str, Any]) -> None:
    def esc(s: Any) -> str:
        return html_mod.escape(str(s) if s is not None else "")

    rows = []
    for r in _flatten_results(report):
        rows.append(
            f"<tr class='{esc(r['state'])}'>"
            f"<td>{esc(r.get('target', ''))}</td>"
            f"<td>{r['port']}</td>"
            f"<td>{esc(r['state'])}</td>"
            f"<td>{esc(r['service'] or '')}</td>"
            f"<td>{esc(r['confidence'] or '')}</td>"
            f"<td>{esc((r['banner'] or '')[:120])}</td>"
            f"</tr>"
        )

    defs: List[str] = []
    if report.get("target_count", 1) <= 1:
        for d in report.get("defensive", []):
            defs.append(
                f"<li><b>{esc(d['service'])}</b> — "
                f"{esc(d['observation'])}<br>"
                f"<i>{esc(d['recommendation'])}</i></li>"
            )
    else:
        for scan in report.get("scans", []):
            tgt = scan["target"]["host"]
            for d in scan.get("defensive", []):
                defs.append(
                    f"<li><b>{esc(tgt)}</b> / "
                    f"<b>{esc(d['service'])}</b> — "
                    f"{esc(d['observation'])}<br>"
                    f"<i>{esc(d['recommendation'])}</i></li>"
                )

    warn_html = "".join(
        f"<li>{esc(w)}</li>" for w in report["warnings"]
    )

    body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>thewatcher report</title>
<style>
 body{{font:14px/1.5 system-ui,Segoe UI,sans-serif;background:#0b0f14;
      color:#d0e0f0;padding:24px;max-width:1100px;margin:auto}}
 h1,h2{{color:#7fffd4}}
 table{{border-collapse:collapse;width:100%;margin:12px 0}}
 th,td{{border:1px solid #1e2a3a;padding:6px 10px;text-align:left}}
 th{{background:#111823}}
 .open{{color:#7fff7f}}.closed{{color:#8899aa}}
 .filtered{{color:#ffcc66}}.unknown{{color:#ff6b6b}}
 code{{background:#0f1823;padding:2px 6px;border-radius:3px}}
</style></head><body>
<h1>thewatcher report</h1>
<p>targets: {report['summary']['targets']}<br>
 time: {esc(report['timestamp'])}<br>
 duration: {report['duration_seconds']}s<br>
 ports per target: {report['summary']['ports_scanned_per_target']}<br>
 open: {report['summary']['open']} &middot;
 closed: {report['summary']['closed']} &middot;
 filtered: {report['summary']['filtered']} &middot;
 unknown: {report['summary']['unknown']}</p>
<h2>results</h2>
<table><tr><th>target</th><th>port</th><th>state</th>
<th>service</th><th>confidence</th><th>banner</th></tr>
{''.join(rows)}
</table>
<h2>defensive analysis</h2>
<ul>{''.join(defs) or '<li>(none)</li>'}</ul>
<h2>limitations &amp; warnings</h2>
<ul>{warn_html}</ul>
</body></html>"""

    def _w(p: Path) -> None:
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
    _atomic_write(path, _w)


def emit_json_stdout(report: Dict[str, Any]) -> None:
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def emit_csv_stdout(report: Dict[str, Any]) -> None:
    fields = [
        "target", "target_ip",
        "port", "state", "service", "product", "version",
        "confidence", "banner", "notes", "error",
    ]
    w = csv.DictWriter(
        sys.stdout, fieldnames=fields, extrasaction="ignore"
    )
    w.writeheader()
    for row in _flatten_results(report):
        row = dict(row)
        row["notes"] = ";".join(row.get("notes") or [])
        w.writerow(row)


# ===========================================================================
# history
# ===========================================================================
def default_reports_dir() -> Path:
    base = os.environ.get("THEWATCHER_HOME") or os.path.join(
        os.path.expanduser("~"), ".thewatcher"
    )
    d = Path(base) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_report(reports_dir: Path, report: Dict[str, Any]) -> Path:
    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    if report.get("target_count", 1) > 1:
        suffix = f"multi-{report['target_count']}"
    else:
        suffix = re.sub(
            r"[^A-Za-z0-9._-]",
            "_",
            report["target"]["host"],
        )[:64]
    path = reports_dir / f"{ts}_{suffix}.json"
    write_json(path, report)
    return path


def list_reports(reports_dir: Path) -> List[Path]:
    return sorted(
        reports_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


def load_report(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ===========================================================================
# diff
# ===========================================================================
def diff_reports(
    a: Dict[str, Any], b: Dict[str, Any]
) -> Dict[str, List[Dict[str, Any]]]:
    def index(rep: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
        return {r["port"]: r for r in rep.get("results", [])}

    ka, kb = index(a), index(b)
    newly_open: List[Dict[str, Any]] = []
    no_longer_open: List[Dict[str, Any]] = []
    service_changed: List[Dict[str, Any]] = []

    for p, rb in kb.items():
        ra = ka.get(p)
        if rb.get("state") == "open" and (
            ra is None or ra.get("state") != "open"
        ):
            newly_open.append(
                {"port": p, "service": rb.get("service")}
            )
        if (
            ra and ra.get("state") == "open"
            and rb.get("state") == "open"
            and (ra.get("service") or "") != (rb.get("service") or "")
        ):
            service_changed.append({
                "port": p,
                "before": ra.get("service"),
                "after": rb.get("service"),
            })

    for p, ra in ka.items():
        rb = kb.get(p)
        if ra.get("state") == "open" and (
            rb is None or rb.get("state") != "open"
        ):
            no_longer_open.append(
                {"port": p, "service": ra.get("service")}
            )

    return {
        "newly_open": newly_open,
        "no_longer_open": no_longer_open,
        "service_changed": service_changed,
    }


# ===========================================================================
# short flag preprocessing (backward compat)
# ===========================================================================
_ALIASES = {
    "-hide": "--hide",
    "-change": "--change",
    "-no_noise": "--slow",
    "-noise": "--slow",
}


def preprocess_argv(argv: List[str]) -> List[str]:
    argv = [_ALIASES.get(a, a) for a in argv]

    ports: List[Tuple[int, int]] = []
    existing: List[Tuple[int, int]] = []
    out: List[str] = []
    i = 0
    in_cluster = False
    subcommands = {"scan", "diff", "history", "list", "show", "rm"}

    while i < len(argv):
        a = argv[i]

        if a in subcommands:
            in_cluster = False
            out.append(a)
            i += 1
            continue

        if a == "--ports" and i + 1 < len(argv):
            try:
                existing.extend(parse_ports_spec(argv[i + 1]))
                i += 2
                continue
            except ArgError:
                out.append(a)
                out.append(argv[i + 1])
                i += 2
                continue

        if a.startswith("--ports="):
            try:
                existing.extend(parse_ports_spec(a.split("=", 1)[1]))
                i += 1
                continue
            except ArgError:
                out.append(a)
                i += 1
                continue

        m = re.fullmatch(r"-(\d{1,5})-(\d{1,5})", a)
        if m:
            s, e = int(m.group(1)), int(m.group(2))
            if MIN_PORT <= s <= e <= MAX_PORT:
                ports.append((s, e))
                in_cluster = True
                i += 1
                continue

        m = re.fullmatch(r"-(\d{1,5})", a)
        if m:
            n = int(m.group(1))
            if MIN_PORT <= n <= MAX_PORT:
                if n >= RANGE_THRESHOLD:
                    ports.append((1, n))
                else:
                    ports.append((n, n))
                in_cluster = True
                i += 1
                continue

        if in_cluster and re.fullmatch(r"\d{1,5}", a):
            n = int(a)
            if MIN_PORT <= n <= MAX_PORT:
                ports.append((n, n))
                i += 1
                continue

        in_cluster = False
        out.append(a)
        i += 1

    merged = existing + ports
    if merged:
        spec = ",".join(
            f"{a}-{b}" if a != b else str(a) for a, b in merged
        )
        out.append(f"--ports={spec}")

    return out


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="thewatcher",
        description="async TCP connect scanner (CLI only). By The Watcher.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "target specs:\n"
            "  1.2.3.4                       single IP\n"
            "  example.com                   single hostname\n"
            "  1.2.3.4,5.6.7.8               comma-separated\n"
            "  192.168.1.1-192.168.1.254     IPv4 range\n"
            "  192.168.1.0/24                IPv4 CIDR (max 4096 hosts)\n"
            "  http://1.2.3.4:8080           URL with explicit port\n"
            "\n"
            "short flag compatibility:\n"
            "  -1000        expand 1..1000 (N >= 1000 -> range)\n"
            "  -80 443      exactly ports 80 and 443\n"
            "  -1-1024      explicit range\n"
            "  -hide        quiet: only open port numbers on stdout\n"
            "  -change      rotate User-Agent, shuffle order, jitter\n"
            "  -s           polite / slow mode (lower rate, longer timeout)\n"
            "  -p PROXY     socks5:// or http:// proxy\n"
            "\n"
            "exit codes:\n"
            "  0 success   1 error   2 invalid args   130 interrupted\n"
        ),
    )
    p.add_argument(
        "--version", action="version",
        version=f"thewatcher {VERSION}",
    )

    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser(
        "scan", help="scan a target",
        description="scan one or more TCP targets",
    )
    s.add_argument(
        "target", nargs="?", default=None,
        help="hostname, IP, range, CIDR, or comma-separated list",
    )
    s.add_argument(
        "-u", "--url", dest="target_url", default=None,
        help="target (alias for positional; backward compatible)",
    )
    s.add_argument(
        "--ports", default=None,
        help="comma-separated port specs, e.g. '80,443,8000-8100'",
    )
    s.add_argument(
        "--profile", choices=("quick", "standard", "custom"),
        default="custom",
        help="port profile (default: custom)",
    )
    s.add_argument(
        "-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
        help=f"max concurrent connections (default {DEFAULT_CONCURRENCY})",
    )
    s.add_argument(
        "-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
        help=f"per-connection timeout in seconds (default {DEFAULT_TIMEOUT})",
    )
    s.add_argument(
        "-p", "--proxy", default=None,
        help="socks5://user:pass@host:port or http://host:port",
    )
    s.add_argument(
        "--change", action="store_true",
        help="rotate User-Agent for HTTP probes, shuffle ports, jitter",
    )
    s.add_argument(
        "-s", "--slow", dest="polite", action="store_true",
        help="polite mode: reduce concurrency, longer timeout, add jitter",
    )
    s.add_argument(
        "--hide", dest="hide", action="store_true",
        help="quiet mode: only open port numbers on stdout",
    )
    s.add_argument("--no-color", action="store_true")
    s.add_argument(
        "--no-service-detect", dest="service_detect",
        action="store_false", default=True,
        help="disable banner-based service detection",
    )
    s.add_argument(
        "--tls-probe", action="store_true",
        help="force TLS probe on every open port (slower)",
    )
    s.add_argument(
        "--json", metavar="PATH", default=None,
        help="write JSON report ('-' for stdout)",
    )
    s.add_argument(
        "--csv", metavar="PATH", default=None,
        help="write CSV report ('-' for stdout)",
    )
    s.add_argument(
        "--html", metavar="PATH", default=None,
        help="write HTML report",
    )
    s.add_argument(
        "--save", action="store_true",
        help="save to default history dir (~/.thewatcher/reports)",
    )
    s.add_argument(
        "--reports-dir", default=None,
        help="override history directory",
    )

    d = sp.add_parser("diff", help="compare two JSON reports")
    d.add_argument("a")
    d.add_argument("b")

    h = sp.add_parser("history", help="manage saved reports")
    hsub = h.add_subparsers(dest="hcmd", required=True)
    hsub.add_parser("list", help="list saved reports")
    hshow = hsub.add_parser("show", help="print a saved report")
    hshow.add_argument("id")
    hrm = hsub.add_parser("rm", help="remove a saved report")
    hrm.add_argument("id")
    hrm.add_argument(
        "-y", "--yes", action="store_true",
        help="confirm removal",
    )

    return p


# ===========================================================================
# command handlers
# ===========================================================================
def _resolve_ports(args, targets: List[str]) -> List[int]:
    if args.profile == "quick":
        return list(QUICK_PORTS)
    if args.profile == "standard":
        return sorted(set(STANDARD_PORTS))
    if args.ports:
        return expand_ports(parse_ports_spec(args.ports))
    if len(targets) == 1:
        p = extract_url_port(targets[0])
        if p:
            return [p]
    raise ArgError(
        "--ports required for custom profile "
        "(or use --profile quick/standard, "
        "or pass a URL with explicit port like http://host:8080)"
    )


def cmd_scan(args) -> int:
    if args.no_color:
        Term.disable()

    target_spec = args.target or args.target_url
    if not target_spec:
        print("error: no target (positional or -u/--url)", file=sys.stderr)
        return EXIT_ARGS

    try:
        targets = expand_targets(target_spec)
    except ArgError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ARGS

    try:
        ports = _resolve_ports(args, targets)
    except ArgError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ARGS
    if not ports:
        print("error: no ports to scan", file=sys.stderr)
        return EXIT_ARGS

    proxy = None
    if args.proxy:
        try:
            proxy = parse_proxy(args.proxy)
        except ArgError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ARGS

    concurrency = max(1, args.concurrency)
    timeout = max(0.05, args.timeout)
    if args.polite:
        concurrency = min(concurrency, POLITE_CONCURRENCY)
        timeout = max(timeout, POLITE_TIMEOUT)

    if args.change:
        random.shuffle(ports)

    stdout_is_machine = (args.json == "-") or (args.csv == "-")
    human = (not args.hide) and (not stdout_is_machine)
    multi = len(targets) > 1

    if human:
        if multi:
            short = target_spec if len(target_spec) <= 60 else target_spec[:57] + "..."
            print(f"{Term.bold('targets')}   : {len(targets)} ({short})")
        else:
            print(f"{Term.bold('target')}    : {targets[0]}")
        print(f"{Term.bold('profile')}   : {args.profile}")
        print(f"{Term.bold('ports')}     : {len(ports)}")
        print(f"{Term.bold('threads')}   : {concurrency}")
        print(f"{Term.bold('timeout')}   : {timeout}s")
        print(
            f"{Term.bold('service')}   : "
            f"{'on' if args.service_detect else 'off'}"
        )
        if proxy:
            print(f"{Term.bold('proxy')}     : {proxy.url()}")
        if args.polite:
            print(f"{Term.bold('mode')}      : polite (rate-limited)")
        if args.change:
            print(f"{Term.bold('change')}    : ua + shuffle + jitter")
        if len(ports) > PORT_COUNT_WARN:
            print(Term.yellow(
                f"warning: {len(ports)} ports x {len(targets)} targets "
                f"= {len(ports) * len(targets)} connections"
            ))
        print()

    scans_out: List[Tuple[str, str, List[PortResult], float]] = []
    errors: List[str] = []

    def on_target_start(target: str, idx: int, total: int) -> None:
        if human and multi:
            print(f"{Term.bold(f'[{idx}/{total}]')} {target}", flush=True)

    def on_result(
        target: str, res: PortResult, done: int, total: int
    ) -> None:
        if args.hide or stdout_is_machine:
            if res.state == "open":
                if multi:
                    print(f"{target}:{res.port}")
                else:
                    print(res.port)
            return
        if res.state == "open":
            line = f"{Term.green('OPEN')} {res.port}/tcp"
            if res.service:
                line += f"  {Term.dim(res.service)}"
                if res.confidence:
                    line += f" {Term.dim('[' + res.confidence + ']')}"
            if multi:
                line = f"  {line}"
            print(line, flush=True)
        if (
            Term.COLOR
            and not args.polite
            and sys.stderr.isatty()
        ):
            sys.stderr.write(f"\r{Term.dim(f'{done}/{total}')}")
            sys.stderr.flush()

    def on_target_done(target: str, ip: str, elapsed: float) -> None:
        if Term.COLOR and human and sys.stderr.isatty():
            sys.stderr.write("\r" + " " * 40 + "\r")
        if not (human and multi):
            return
        if not ip:
            print(Term.red(f"  failed: {target}"))
            print()
            return
        results_this = next(
            (s[2] for s in scans_out if s[0] == target), []
        )
        n_open = sum(1 for r in results_this if r.state == "open")
        print(Term.dim(
            f"  done: {n_open} open / {len(results_this)} scanned "
            f"/ {elapsed:.2f}s"
        ))
        print()

    overall_elapsed = 0.0
    try:
        overall_elapsed = asyncio.run(scan_targets(
            targets, ports, timeout, concurrency, proxy,
            args.service_detect, args.change, args.polite,
            args.tls_probe, on_target_start, on_result,
            on_target_done, scans_out, errors,
        ))
    except KeyboardInterrupt:
        if Term.COLOR and not stdout_is_machine and not args.hide:
            sys.stderr.write("\r" + " " * 40 + "\r")
        print("\ninterrupted", file=sys.stderr)
        if scans_out:
            total_open = sum(
                1 for _t, _i, rs, _e in scans_out
                for r in rs if r.state == "open"
            )
            print(
                f"partial: {len(scans_out)}/{len(targets)} targets, "
                f"{total_open} open (results not written)",
                file=sys.stderr,
            )
        return EXIT_INTERRUPTED
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_ERR

    warnings: List[str] = []
    if args.service_detect:
        warnings.append(
            "service detection is conservative: 'confirmed' means a "
            "matching banner was observed; 'likely'/'guess' are inferred"
        )
    if proxy:
        warnings.append(
            "scan routed through proxy; proxy failures are reported as "
            "'unknown' with error=proxy_failure"
        )
    warnings.append(
        "TCP connect cannot distinguish filtered from silently-dropped; "
        "timeouts are reported as 'filtered', not confirmed-filtered"
    )
    if args.polite:
        warnings.append(
            "polite mode: reduced concurrency, longer timeout, jittered "
            "connections; scan takes longer by design"
        )
    if multi:
        warnings.append(
            "multi-target scan: each target is scanned sequentially; "
            "diff requires single-target reports"
        )

    config = {
        "profile": args.profile,
        "concurrency": concurrency,
        "timeout": timeout,
        "service_detection": args.service_detect,
        "proxy": proxy.url() if proxy else None,
        "polite": args.polite,
        "change_user_agent": args.change,
        "tls_probe": args.tls_probe,
        "target_count": len(targets),
    }

    report = build_report(
        scans_out, ports, overall_elapsed, config, errors, warnings,
    )

    exit_code = EXIT_OK if not errors else EXIT_ERR

    if args.json and args.json != "-":
        try:
            write_json(Path(args.json), report)
            if human:
                print(f"json     : {args.json}")
        except OSError as e:
            print(f"error writing JSON: {e}", file=sys.stderr)
            exit_code = EXIT_ERR

    if args.csv and args.csv != "-":
        try:
            write_csv(Path(args.csv), report)
            if human:
                print(f"csv      : {args.csv}")
        except OSError as e:
            print(f"error writing CSV: {e}", file=sys.stderr)
            exit_code = EXIT_ERR

    if args.html:
        try:
            write_html(Path(args.html), report)
            if human:
                print(f"html     : {args.html}")
        except OSError as e:
            print(f"error writing HTML: {e}", file=sys.stderr)
            exit_code = EXIT_ERR

    if args.save:
        rd = (
            Path(args.reports_dir)
            if args.reports_dir
            else default_reports_dir()
        )
        try:
            saved = save_report(rd, report)
            if human:
                print(f"saved    : {saved}")
        except OSError as e:
            print(f"error saving: {e}", file=sys.stderr)
            exit_code = EXIT_ERR

    if args.json == "-":
        emit_json_stdout(report)
    elif args.csv == "-":
        emit_csv_stdout(report)

    if human:
        s = report["summary"]
        print()
        print(Term.bold("grand summary:"))
        print(f"  targets   : {s['targets']}")
        print(f"  duration  : {overall_elapsed:.2f}s")
        print(f"  ports/tgt : {s['ports_scanned_per_target']}")
        print(f"  {Term.green('open')}      : {s['open']}")
        print(f"  closed    : {s['closed']}")
        print(f"  {Term.yellow('filtered')}  : {s['filtered']}")
        print(f"  unknown   : {s['unknown']}")
        if not multi and report.get("defensive"):
            print()
            print(Term.bold("defensive notes:"))
            for d in report["defensive"]:
                print(
                    f"  {Term.yellow('!')} {d['port']} "
                    f"{d['service']}: {d['recommendation']}"
                )
        if warnings:
            print()
            print(Term.bold("limitations:"))
            for w in warnings:
                print(f"  {Term.dim('-')} {w}")
        if errors:
            print()
            print(Term.bold(Term.red("errors:")))
            for e in errors:
                print(f"  {Term.red('-')} {e}")
        print()
        print("By The Watcher.")

    return exit_code


def cmd_diff(args) -> int:
    try:
        a = load_report(Path(args.a))
        b = load_report(Path(args.b))
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERR
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON: {e}", file=sys.stderr)
        return EXIT_ERR

    for key, rep in (("first", a), ("second", b)):
        if rep.get("tool") != "thewatcher":
            print(
                f"error: {key} file is not a thewatcher report",
                file=sys.stderr,
            )
            return EXIT_ERR
        if rep.get("target_count", 1) > 1:
            print(
                f"error: {key} report has {rep['target_count']} targets; "
                f"diff requires single-target reports",
                file=sys.stderr,
            )
            print(
                "hint: scan one target at a time for history-based diff",
                file=sys.stderr,
            )
            return EXIT_ERR

    diff = diff_reports(a, b)

    print(Term.bold("newly open:"))
    for item in diff["newly_open"]:
        extra = item.get("service") or ""
        print(f"  {Term.green('+')} {item['port']}/tcp {extra}")
    if not diff["newly_open"]:
        print("  (none)")

    print(Term.bold("no longer open:"))
    for item in diff["no_longer_open"]:
        extra = item.get("service") or ""
        print(f"  {Term.red('-')} {item['port']}/tcp {extra}")
    if not diff["no_longer_open"]:
        print("  (none)")

    print(Term.bold("service changed:"))
    for item in diff["service_changed"]:
        print(
            f"  {Term.yellow('~')} {item['port']}/tcp "
            f"{item['before']} -> {item['after']}"
        )
    if not diff["service_changed"]:
        print("  (none)")

    return EXIT_OK


def cmd_history(args) -> int:
    rd = default_reports_dir()
    if args.hcmd == "list":
        reports = list_reports(rd)
        if not reports:
            print(f"(no reports in {rd})")
            return EXIT_OK
        for p in reports:
            ts = datetime.datetime.fromtimestamp(
                p.stat().st_mtime
            )
            print(f"{ts.strftime('%Y-%m-%d %H:%M:%S')}  {p.name}")
        return EXIT_OK

    if args.hcmd == "show":
        matches = list(rd.glob(f"*{args.id}*.json"))
        if not matches:
            print(
                f"error: no report matching {args.id}",
                file=sys.stderr,
            )
            return EXIT_ERR
        try:
            with open(matches[0], "r", encoding="utf-8") as f:
                print(f.read())
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERR
        return EXIT_OK

    if args.hcmd == "rm":
        matches = list(rd.glob(f"*{args.id}*.json"))
        if not matches:
            print(
                f"error: no report matching {args.id}",
                file=sys.stderr,
            )
            return EXIT_ERR
        if not args.yes:
            print("would remove:", file=sys.stderr)
            for m in matches:
                print(f"  {m}", file=sys.stderr)
            print(
                "re-run with -y/--yes to confirm", file=sys.stderr
            )
            return EXIT_ARGS
        for m in matches:
            m.unlink()
        print(f"removed {len(matches)} file(s)")
        return EXIT_OK

    return EXIT_ARGS


# ===========================================================================
# entry point
# ===========================================================================
def _main_impl(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = preprocess_argv(argv)

    subcommands = {"scan", "diff", "history"}
    has_sub = any(a in subcommands for a in argv)
    has_meta = any(a in ("-h", "--help", "--version") for a in argv)
    if not has_sub and not has_meta:
        argv.insert(0, "scan")

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if e.code is not None else EXIT_ARGS

    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "diff":
        return cmd_diff(args)
    if args.cmd == "history":
        return cmd_history(args)
    return EXIT_ARGS


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Wraps KeyboardInterrupt so console_scripts and
    `python thewatcher.py` behave identically."""
    try:
        return _main_impl(argv)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())