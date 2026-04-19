"""
port-scanner · scanner.py
Módulo principal de varredura de portas com suporte a TCP e banner grabbing.
"""

import socket
import concurrent.futures
import json
import csv
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

# Serviços comuns por porta
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


@dataclass
class PortResult:
    port: int
    state: str          # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class ScanResult:
    target: str
    ip: str
    scan_start: str
    scan_end: str = ""
    total_ports: int = 0
    open_ports: int = 0
    results: list = field(default_factory=list)


def resolve_target(target: str) -> str:
    """Resolve hostname para IP - Levanta exceção se não encontrar."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Não foi possível resolver '{target}': {e}")


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Tenta capturar o banner de um serviço aberto."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(1024)
            return data.decode("utf-8", errors="replace").strip()[:200]
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> PortResult:
    """Testa conectividade TCP em uma porta específica."""
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000
            service = COMMON_SERVICES.get(port, "unknown")
            banner = grab_banner(ip, port) if grab_banners else ""
            return PortResult(port, "open", service, banner, round(latency, 2))
    except (ConnectionRefusedError, socket.timeout):
        latency = (time.monotonic() - start) * 1000
        return PortResult(port, "closed", latency_ms=round(latency, 2))
    except OSError:
        return PortResult(port, "filtered")


def parse_ports(port_arg: str) -> list[int]:
    """
    Converte string de portas em lista de inteiros.
    Aceita: '80', '80,443', '1-1024', '22,80,8000-8080'
    """
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start_p, end_p = part.split("-", 1)
            ports.extend(range(int(start_p), int(end_p) + 1))
        else:
            ports.append(int(part))

    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        raise ValueError(f"Portas inválidas: {invalid}")
    return sorted(set(ports))


def run_scan(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    threads: int = 100,
    grab_banners: bool = False,
    open_only: bool = True,
) -> ScanResult:
    """
    Executa o scan paralelo e retorna um ScanResult.

    Args:
        target:       Hostname ou IP do alvo.
        ports:        Lista de portas a varrer.
        timeout:      Timeout de conexão em segundos.
        threads:      Número máximo de threads paralelas.
        grab_banners: Se True, tenta capturar banner de portas abertas.
        open_only:    Se True, inclui apenas portas abertas no resultado.
    """
    ip = resolve_target(target)
    result = ScanResult(
        target=target,
        ip=ip,
        scan_start=datetime.now().isoformat(timespec="seconds"),
        total_ports=len(ports),
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab_banners): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            port_result = future.result()
            if not open_only or port_result.state == "open":
                result.results.append(port_result)

    result.results.sort(key=lambda r: r.port)
    result.open_ports = sum(1 for r in result.results if r.state == "open")
    result.scan_end = datetime.now().isoformat(timespec="seconds")
    return result


# ── Exportadores ─────────────────────────────────────────────────────────────

def export_json(result: ScanResult, filepath: str) -> None:
    data = asdict(result)
    data["results"] = [asdict(r) for r in result.results]
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_csv(result: ScanResult, filepath: str) -> None:
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["port", "state", "service", "banner", "latency_ms"]
        )
        writer.writeheader()
        for r in result.results:
            writer.writerow(asdict(r))


def export_txt(result: ScanResult, filepath: str) -> None:
    lines = [
        f"Port Scanner Report",
        f"===================",
        f"Target  : {result.target} ({result.ip})",
        f"Started : {result.scan_start}",
        f"Finished: {result.scan_end}",
        f"Scanned : {result.total_ports} ports — {result.open_ports} open",
        "",
        f"{'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'LATENCY':>10}   BANNER",
        "-" * 70,
    ]
    for r in result.results:
        banner_preview = r.banner[:40].replace("\n", " ") if r.banner else ""
        lines.append(
            f"{r.port:<8} {r.state:<10} {r.service:<15} {r.latency_ms:>8.1f}ms"
            + (f"   {banner_preview}" if banner_preview else "")
        )
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))