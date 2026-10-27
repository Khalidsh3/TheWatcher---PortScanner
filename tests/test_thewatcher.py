"""
Local-only tests. No internet access. Uses loopback servers.
Run: python -m pytest -v tests/
"""
import asyncio
import csv
import json
import socket
from pathlib import Path

import pytest

import thewatcher as tw


# ---------------------------------------------------------------------------
# port parsing
# ---------------------------------------------------------------------------
class TestPortParsing:
    def test_single_port(self):
        assert tw.parse_ports_spec("80") == [(80, 80)]

    def test_range(self):
        assert tw.parse_ports_spec("1-1024") == [(1, 1024)]

    def test_comma_mixed(self):
        assert tw.parse_ports_spec("22,80-82,443") == [
            (22, 22), (80, 82), (443, 443)
        ]

    def test_reversed_range_normalized(self):
        assert tw.parse_ports_spec("100-50") == [(50, 100)]

    def test_out_of_range(self):
        with pytest.raises(tw.ArgError):
            tw.parse_ports_spec("0")
        with pytest.raises(tw.ArgError):
            tw.parse_ports_spec("65536")

    def test_invalid(self):
        with pytest.raises(tw.ArgError):
            tw.parse_ports_spec("abc")
        with pytest.raises(tw.ArgError):
            tw.parse_ports_spec("1-")

    def test_expand_dedupes(self):
        assert tw.expand_ports([(1, 3), (2, 4)]) == [1, 2, 3, 4]


# ---------------------------------------------------------------------------
# argv preprocessing
# ---------------------------------------------------------------------------
class TestPreprocess:
    def test_dash_1000_range(self):
        out = tw.preprocess_argv(["-u", "x", "-1000"])
        assert "--ports=1-1000" in out

    def test_dash_80_single(self):
        out = tw.preprocess_argv(["-u", "x", "-80"])
        assert "--ports=80" in out

    def test_dash_80_443_cluster(self):
        out = tw.preprocess_argv(["-u", "x", "-80", "443"])
        assert "--ports=80,443" in out

    def test_explicit_range(self):
        out = tw.preprocess_argv(["-u", "x", "-1-1024"])
        assert "--ports=1-1024" in out

    def test_hide_alias(self):
        out = tw.preprocess_argv(["-hide", "-u", "x", "-80"])
        assert "--hide" in out

    def test_change_alias(self):
        out = tw.preprocess_argv(["-change", "-u", "x", "-80"])
        assert "--change" in out

    def test_no_noise_alias(self):
        out = tw.preprocess_argv(["-no_noise", "-u", "x", "-80"])
        assert "--slow" in out

    def test_merge_explicit_and_short(self):
        out = tw.preprocess_argv(["-u", "x", "--ports", "22", "-80"])
        assert any(
            a.startswith("--ports=") and "22" in a and "80" in a
            for a in out
        )


# ---------------------------------------------------------------------------
# target parsing
# ---------------------------------------------------------------------------
class TestTarget:
    def test_plain_hostname(self):
        assert tw.parse_target("example.com") == "example.com"

    def test_url(self):
        assert tw.parse_target("https://example.com/path") == "example.com"

    def test_ipv4(self):
        assert tw.parse_target("127.0.0.1") == "127.0.0.1"

    def test_empty(self):
        with pytest.raises(tw.ArgError):
            tw.parse_target("")


# ---------------------------------------------------------------------------
# proxy parsing
# ---------------------------------------------------------------------------
class TestProxy:
    def test_socks5_default_port(self):
        p = tw.parse_proxy("socks5://1.2.3.4")
        assert p.host == "1.2.3.4"
        assert p.port == 1080

    def test_http_default_port(self):
        p = tw.parse_proxy("http://proxy")
        assert p.port == 8080

    def test_bare_host_becomes_socks5(self):
        p = tw.parse_proxy("1.2.3.4:9999")
        assert p.scheme == "socks5"
        assert p.port == 9999

    def test_bad_scheme(self):
        with pytest.raises(tw.ArgError):
            tw.parse_proxy("ftp://x")


# ---------------------------------------------------------------------------
# scan against localhost
# ---------------------------------------------------------------------------
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class TestLocalhostScan:
    def test_open_and_closed(self):
        async def _run():
            async def _handler(r, w):
                w.close()
            srv = await asyncio.start_server(
                _handler, "127.0.0.1", 0
            )
            open_port = srv.sockets[0].getsockname()[1]
            try:
                res_open = await tw.scan_port(
                    "127.0.0.1", "127.0.0.1", open_port,
                    None, 2.0, False, False, False,
                )
                res_closed = await tw.scan_port(
                    "127.0.0.1", "127.0.0.1",
                    _free_port(), None, 1.0, False, False, False,
                )
                return res_open, res_closed
            finally:
                srv.close()
                await srv.wait_closed()

        r_open, r_closed = asyncio.run(_run())
        assert r_open.state == "open"
        assert r_closed.state in ("closed", "filtered")


# ---------------------------------------------------------------------------
# report / serialization
# ---------------------------------------------------------------------------
def _sample_report():
    results = [
        tw.PortResult(port=22, state="open", service="ssh",
                      confidence="confirmed"),
        tw.PortResult(port=80, state="closed"),
    ]
    return tw.build_report(
        "example.com", "93.184.216.34",
        [22, 80], results, 1.23,
        {"profile": "custom"}, [], ["test warning"],
    )


class TestReport:
    def test_json_roundtrip(self, tmp_path: Path):
        rep = _sample_report()
        out = tmp_path / "r.json"
        tw.write_json(out, rep)
        loaded = tw.load_report(out)
        assert loaded["summary"]["open"] == 1
        assert loaded["summary"]["closed"] == 1
        assert loaded["target"]["host"] == "example.com"

    def test_csv_written(self, tmp_path: Path):
        rep = _sample_report()
        out = tmp_path / "r.csv"
        tw.write_csv(out, rep)
        rows = list(csv.DictReader(out.open()))
        assert len(rows) == 2
        assert rows[0]["port"] == "22"
        assert rows[0]["state"] == "open"

    def test_html_written(self, tmp_path: Path):
        rep = _sample_report()
        out = tmp_path / "r.html"
        tw.write_html(out, rep)
        body = out.read_text(encoding="utf-8")
        assert "thewatcher report" in body
        assert "22" in body


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
class TestDiff:
    def test_diff_basic(self):
        a = {
            "tool": "thewatcher",
            "results": [
                {"port": 22, "state": "open", "service": "ssh"},
                {"port": 80, "state": "open", "service": "http"},
            ],
        }
        b = {
            "tool": "thewatcher",
            "results": [
                {"port": 22, "state": "open", "service": "ssh-v2"},
                {"port": 80, "state": "closed"},
                {"port": 443, "state": "open", "service": "https"},
            ],
        }
        d = tw.diff_reports(a, b)
        assert any(x["port"] == 443 for x in d["newly_open"])
        assert any(x["port"] == 80 for x in d["no_longer_open"])
        assert any(x["port"] == 22 for x in d["service_changed"])


# ---------------------------------------------------------------------------
# defensive analysis
# ---------------------------------------------------------------------------
class TestDefensive:
    def test_ssh_flagged(self):
        results = [tw.PortResult(port=22, state="open")]
        d = tw.defensive_analysis(results)
        assert any(x["service"] == "SSH" for x in d)

    def test_closed_not_flagged(self):
        results = [tw.PortResult(port=22, state="closed")]
        assert tw.defensive_analysis(results) == []


# ---------------------------------------------------------------------------
# CLI smoke
# ---------------------------------------------------------------------------
class TestCLI:
    def test_help_exits_zero(self):
        with pytest.raises(SystemExit) as ei:
            tw._main_impl(["--help"])
        assert ei.value.code == 0

    def test_version_exits_zero(self):
        with pytest.raises(SystemExit) as ei:
            tw._main_impl(["--version"])
        assert ei.value.code == 0

    def test_missing_ports_custom_profile(self):
        code = tw._main_impl(["scan", "-u", "example.com"])
        assert code == tw.EXIT_ARGS