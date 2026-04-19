# Port Scanner

Scanner de portas TCP multi-thread escrito em Python puro.
Desenvolvido como projeto de estudo de cibersegurança.



# Funcionalidades

- Varredura TCP paralela com `ThreadPoolExecutor` — 
- Banner grabbing  opcional para identificar versões de serviços
- Resolução de hostname  automática
- Atalho `top100`  com as 100 portas mais comuns
- Exportação de resultados em JSON, CSV ou TXT
- Testes unitários com pytest e cobertura de código

---

##  Estrutura

```
port-scanner/
├── cli.py              # Ponto de entrada — interface de linha de comando
├── src/
│   └── scanner.py      # Lógica de scan, modelos de dados e exportadores
├── tests/
│   └── test_scanner.py # Testes unitários e de integração leve
├── output/             # Resultados exportados (ignorado pelo git)
├── docs/
│   └── exemplos.md     # Exemplos de uso e casos de estudo
├── requirements.txt
└── .gitignore
```

---

##  Como usar

### Instalação

```bash
git clone https://github.com/seuusuario/port-scanner.git
cd port-scanner
pip install -r requirements.txt   # apenas pytest para testes
```

> O scanner em si não tem dependências externas — usa somente a stdlib do Python 3.10+.

### Exemplos

```bash
# Varrer as portas 1-1024 do host de teste oficial do nmap
python cli.py scanme.nmap.org -p 1-1024

# Portas específicas com captura de banner
python cli.py 192.168.1.1 -p 22,80,443,3306 --banners

# Top 100 portas comuns, exportar como JSON
python cli.py example.com -p top100 -o json

# Scan rápido de range grande com mais threads
python cli.py 10.0.0.1 -p 1-10000 -t 500 --timeout 0.3

# Mostrar portas fechadas também
python cli.py 192.168.1.1 -p 80-90 --all
```

### Saída esperada

```
  Alvo     : scanme.nmap.org
  Portas   : 1024 porta(s)
  Threads  : 100
  Timeout  : 1.0s

  ✔  Scan concluído em 8.43s

Resultado: 4 porta(s) abertas em 45.33.32.156

PORT     STATE        SERVICE          LATENCY   BANNER
────────────────────────────────────────────────────────────────────────
22       open         SSH              142.3ms
80       open         HTTP             138.7ms   HTTP/1.1 200 OK ...
443      open         HTTPS            140.1ms
9929     open         unknown          141.9ms
```

---

##  Argumentos

| Argumento       | Padrão    | Descrição                                      |
|-----------------|-----------|------------------------------------------------|
| `target`        | —         | IP ou hostname do alvo (obrigatório)           |
| `-p / --ports`  | `1-1024`  | Portas: `80`, `22,80,443`, `1-1024`, `top100`  |
| `-t / --threads`| `100`     | Threads paralelas                               |
| `--timeout`     | `1.0`     | Timeout por porta (segundos)                   |
| `--banners`     | desligado | Tentar capturar banner dos serviços            |
| `--all`         | desligado | Mostrar portas fechadas também                 |
| `-o / --output` | —         | Exportar resultado: `json`, `csv` ou `txt`     |

---

## Testes

```bash
# Rodar todos os testes
pytest tests/ -v

# Com cobertura de código
pytest tests/ --cov=src --cov-report=term-missing
```

---

##  Como funciona

```
cli.py (argparse + UI)
    │
    └─► scanner.run_scan()
            │
            ├─► resolve_target()      # socket.gethostbyname
            │
            ├─► ThreadPoolExecutor    # N threads paralelas
            │       └─► scan_port()  # socket.create_connection (TCP)
            │               └─► grab_banner() [opcional]
            │
            └─► ScanResult           # dataclass com todos os resultados
                    ├─► export_json()
                    ├─► export_csv()
                    └─► export_txt()
```

**Por que TCP connect scan?**
O método `connect()` completa o handshake TCP de três vias — é o método mais confiável e não requer privilégios de root. A desvantagem é que ele é mais detectável por firewalls e IDS comparado a técnicas stealth (SYN scan), que exigiriam raw sockets.

---

##  Conceitos abordados

- **Sockets TCP** — `socket.create_connection` e timeout
- **Concorrência** — `ThreadPoolExecutor` com `as_completed`
- **Dataclasses** — modelagem de dados com `@dataclass`
- **CLI profissional** — `argparse` com subcomandos e epilog
- **Exportação de dados** — JSON, CSV, TXT formatado
- **Testes** — `pytest` com fixtures e casos de borda

---

##  Possíveis melhorias (contribuições bem-vindas)

- [ ] UDP scan
- [ ] Detecção de OS via TTL
- [ ] Output em HTML interativo
- [ ] Integração com API do Shodan
- [ ] Rate limiting configurável

---

##  Licença

MIT — veja [LICENSE](LICENSE) para detalhes.
