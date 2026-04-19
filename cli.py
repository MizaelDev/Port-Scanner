#!/usr/bin/env python3
"""
port-scanner · cli.py
Interface de linha de comando com saída colorida e barra de progresso.

Uso:
    python cli.py scanme.nmap.org -p 1-1024
    python cli.py 192.168.1.1 -p 22,80,443,3306 --banners -o json
    python cli.py example.com -p top100 -t 200 --timeout 0.5
"""

import argparse
import sys
import time
import os
from pathlib import Path

# Adiciona src/ ao path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from scanner import run_scan, parse_ports, export_json, export_csv, export_txt

# ── Cores ANSI ───────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

# Top 100 portas mais comuns (inspirado em nmap)
TOP100 = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017, 5432, 6379, 11211,
    2049, 2181, 4443, 5000, 5001, 7001, 7002, 7070, 8000, 8008, 8009,
    8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 9000, 9001,
    9002, 9090, 9091, 9200, 9300, 10000, 27018, 28017, 50000, 50070,
    1080, 1194, 1433, 1521, 2375, 2376, 4848, 4984, 5044, 5601, 5672,
    6443, 7474, 7687, 8161, 8500, 8983, 9042, 9092, 9411, 9612, 15672,
    15692, 16010, 16020, 19999, 20000, 24007, 24008, 24009, 24010, 24011,
    32400, 32469, 49152, 49153, 49154, 49155, 49156, 49157, 61616,
]


def banner():
    print(f"""
{CYAN}{BOLD}
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚████║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
{RESET}{GRAY}  TCP Port Scanner · github.com/seuusuario/port-scanner{RESET}
""")


def progress_bar(current: int, total: int, width: int = 35) -> str:
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{CYAN}{bar}{RESET}] {pct*100:5.1f}%  {current}/{total}"


def state_color(state: str) -> str:
    return {
        "open":     f"{GREEN}{BOLD}open{RESET}",
        "closed":   f"{GRAY}closed{RESET}",
        "filtered": f"{YELLOW}filtered{RESET}",
    }.get(state, state)


def print_result_table(result):
    print(f"\n{BOLD}{'PORT':<8} {'STATE':<12} {'SERVICE':<16} {'LATENCY':>10}   BANNER{RESET}")
    print(GRAY + "─" * 72 + RESET)
    for r in result.results:
        banner_preview = r.banner[:40].replace("\n", " ") if r.banner else ""
        banner_str = f"  {GRAY}{banner_preview}{RESET}" if banner_preview else ""
        print(
            f"{WHITE}{r.port:<8}{RESET}"
            f"{state_color(r.state):<20}"
            f"{CYAN}{r.service:<16}{RESET}"
            f"{r.latency_ms:>8.1f}ms"
            f"{banner_str}"
        )


def parse_args():
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description="Scanner de portas TCP com suporte a multi-thread e exportação de resultados.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
exemplos:
  python cli.py scanme.nmap.org -p 1-1024
  python cli.py 192.168.1.1 -p 22,80,443,3306 --banners
  python cli.py example.com -p top100 -t 200 -o json
  python cli.py 10.0.0.1 -p 1-65535 --timeout 0.3 -t 500

⚠  Use apenas em sistemas que você tem autorização para testar.
        """,
    )
    parser.add_argument("target", help="IP ou hostname do alvo")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Portas: '80', '22,80,443', '1-1024', 'top100' (padrão: 1-1024)"
    )
    parser.add_argument("-t", "--threads", type=int, default=100, help="Threads paralelas (padrão: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout por porta em segundos (padrão: 1.0)")
    parser.add_argument("--banners", action="store_true", help="Tentar capturar banners de serviços")
    parser.add_argument("--all", action="store_true", dest="show_all", help="Mostrar portas fechadas também")
    parser.add_argument(
        "-o", "--output", choices=["json", "csv", "txt"],
        help="Exportar resultado (salvo em output/)"
    )
    return parser.parse_args()


def main():
    banner()
    args = parse_args()

    # Resolve lista de portas
    if args.ports.lower() == "top100":
        ports = TOP100
        ports_desc = f"top 100 portas comuns"
    else:
        try:
            ports = parse_ports(args.ports)
            ports_desc = f"{len(ports)} porta(s)"
        except ValueError as e:
            print(f"{RED}Erro:{RESET} {e}")
            sys.exit(1)

    print(f"  {BOLD}Alvo     :{RESET} {CYAN}{args.target}{RESET}")
    print(f"  {BOLD}Portas   :{RESET} {ports_desc}")
    print(f"  {BOLD}Threads  :{RESET} {args.threads}")
    print(f"  {BOLD}Timeout  :{RESET} {args.timeout}s")
    print(f"  {BOLD}Banners  :{RESET} {'sim' if args.banners else 'não'}")
    print()

    # Animação de progresso simples (atualiza a cada 0.3s enquanto scan roda)
    import threading
    done_event = threading.Event()
    scan_result = [None]
    scan_error  = [None]

    def do_scan():
        try:
            scan_result[0] = run_scan(
                target=args.target,
                ports=ports,
                timeout=args.timeout,
                threads=args.threads,
                grab_banners=args.banners,
                open_only=not args.show_all,
            )
        except Exception as e:
            scan_error[0] = e
        finally:
            done_event.set()

    thread = threading.Thread(target=do_scan, daemon=True)
    thread.start()

    t0 = time.time()
    spin = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    while not done_event.is_set():
        elapsed = time.time() - t0
        print(f"\r  {CYAN}{spin[i % len(spin)]}{RESET}  Varrendo... {elapsed:.1f}s", end="", flush=True)
        i += 1
        time.sleep(0.1)

    elapsed = time.time() - t0
    print(f"\r  {GREEN}✔{RESET}  Scan concluído em {elapsed:.2f}s" + " " * 20)

    if scan_error[0]:
        print(f"\n{RED}Erro durante o scan:{RESET} {scan_error[0]}")
        sys.exit(1)

    result = scan_result[0]

    # Resumo
    print(f"\n{BOLD}Resultado:{RESET} {GREEN}{result.open_ports} porta(s) abertas{RESET} em {result.ip}")
    if not result.results:
        print(f"  {GRAY}Nenhuma porta aberta encontrada.{RESET}")
        return

    print_result_table(result)

    # Exportação
    if args.output:
        os.makedirs("output", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S") if True else ""
        from datetime import datetime as dt
        ts = dt.now().strftime("%Y%m%d_%H%M%S")
        fname = f"output/scan_{args.target.replace('.','_')}_{ts}.{args.output}"
        exporters = {"json": export_json, "csv": export_csv, "txt": export_txt}
        exporters[args.output](result, fname)
        print(f"\n  {GREEN}✔{RESET}  Resultado exportado: {CYAN}{fname}{RESET}")

    print()


if __name__ == "__main__":
    main()
