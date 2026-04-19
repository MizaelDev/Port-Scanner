"""
tests/test_scanner.py
Testes unitários para o módulo scanner.py.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner import parse_ports, PortResult, ScanResult


# ── parse_ports ──────────────────────────────────────────────────────────────

class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_multiple_ports(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        result = parse_ports("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_mixed(self):
        result = parse_ports("22,80,8000-8002")
        assert result == [22, 80, 8000, 8001, 8002]

    def test_deduplication(self):
        result = parse_ports("80,80,443")
        assert result == [80, 443]

    def test_sorted_output(self):
        result = parse_ports("443,22,80")
        assert result == [22, 80, 443]

    def test_invalid_port_zero(self):
        with pytest.raises(ValueError):
            parse_ports("0")

    def test_invalid_port_too_high(self):
        with pytest.raises(ValueError):
            parse_ports("65536")

    def test_full_range_boundaries(self):
        result = parse_ports("1-3,65533-65535")
        assert 1 in result and 65535 in result


# ── PortResult ───────────────────────────────────────────────────────────────

class TestPortResult:
    def test_open_port(self):
        r = PortResult(port=80, state="open", service="HTTP", banner="", latency_ms=12.5)
        assert r.state == "open"
        assert r.service == "HTTP"

    def test_closed_port(self):
        r = PortResult(port=9999, state="closed")
        assert r.state == "closed"
        assert r.banner == ""

    def test_filtered_port(self):
        r = PortResult(port=23, state="filtered")
        assert r.state == "filtered"


# ── ScanResult ───────────────────────────────────────────────────────────────

class TestScanResult:
    def test_open_ports_count(self):
        results = [
            PortResult(80, "open", "HTTP"),
            PortResult(443, "open", "HTTPS"),
            PortResult(9999, "closed"),
        ]
        sr = ScanResult(
            target="example.com",
            ip="93.184.216.34",
            scan_start="2024-01-01T00:00:00",
            scan_end="2024-01-01T00:00:05",
            total_ports=3,
            open_ports=2,
            results=results,
        )
        assert sr.open_ports == 2
        assert len(sr.results) == 3


# ── Integração leve (sem rede real) ─────────────────────────────────────────

class TestScannerIntegration:
    """Testes que usam loopback (127.0.0.1) — não requerem internet."""

    def test_scan_localhost_closed(self):
        """Porta 19999 provavelmente fechada no loopback."""
        from scanner import scan_port
        result = scan_port("127.0.0.1", 19999, timeout=0.3, grab_banners=False)
        assert result.state in ("closed", "filtered")

    def test_parse_then_scan_structure(self):
        """Verifica que run_scan retorna ScanResult com estrutura correta."""
        from scanner import run_scan
        result = run_scan(
            target="127.0.0.1",
            ports=[19998, 19999],
            timeout=0.3,
            threads=2,
            grab_banners=False,
            open_only=False,
        )
        assert result.ip == "127.0.0.1"
        assert result.total_ports == 2
        assert isinstance(result.results, list)
