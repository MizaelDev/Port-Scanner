# port-scanner

Scanner de portas TCP feito em Python, sem bibliotecas externas. Fiz esse projeto estudando cibersegurança para entender como ferramentas como o nmap funcionam por baixo.

> **Aviso:** use só em sistemas que você tem autorização para testar. Varrer portas sem permissão é ilegal.

---

## O que ele faz

- Varre portas TCP em paralelo usando threads — 1.000 portas em menos de 10 segundos
- Tenta capturar o banner do serviço (versão, nome, etc.) com `--banners`
- Tem um atalho `top100` com as portas mais comuns tipo SSH, HTTP, MySQL...
- Exporta o resultado em JSON, CSV ou TXT
- Mostra progresso e cores no terminal

## Como rodar

```bash
git clone https://github.com/MizaelDev/port-scanner.git
cd port-scanner
pip install -r requirements.txt
```

O `requirements.txt` só tem o pytest. O scanner em si usa só a stdlib do Python.

```bash
# scanme.nmap.org é um servidor público do nmap feito pra testes
python cli.py scanme.nmap.org -p 1-1024

# portas específicas com banner
python cli.py 192.168.1.1 -p 22,80,443 --banners

# exportar resultado
python cli.py scanme.nmap.org -p top100 -o json
```

Saída no terminal:

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

## Argumentos

| Argumento        | Padrão   | O que faz                                     |
|------------------|----------|-----------------------------------------------|
| `target`         | —        | IP ou hostname (obrigatório)                  |
| `-p / --ports`   | `1-1024` | Portas: `80`, `22,80,443`, `1-1024`, `top100` |
| `-t / --threads` | `100`    | Quantas threads rodar em paralelo             |
| `--timeout`      | `1.0`    | Tempo máximo de espera por porta (segundos)   |
| `--banners`      | off      | Tenta capturar o banner do serviço            |
| `--all`          | off      | Mostra portas fechadas também                 |
| `-o / --output`  | —        | Salva o resultado: `json`, `csv` ou `txt`     |

## Testes

```bash
pytest tests/ -v
```

15 testes cobrindo parse de portas, modelos de dados e integração com loopback.

## Como funciona

O scanner abre uma conexão TCP real em cada porta (TCP connect scan). Se conectar, a porta está aberta. Se recusar ou timeout, está fechada ou filtrada.

Usei `ThreadPoolExecutor` pra rodar várias portas ao mesmo tempo — sem isso, varrer 1.000 portas sequencialmente levaria minutos.

```
cli.py
  └── scanner.run_scan()
        ├── resolve_target()       # transforma hostname em IP
        ├── ThreadPoolExecutor     # threads em paralelo
        │     └── scan_port()     # tenta conectar via TCP
        │           └── grab_banner() [se --banners]
        └── ScanResult            # guarda e exporta os resultados
```

Por que TCP connect e não SYN scan? SYN scan é mais rápido e discreto, mas precisa de raw sockets e permissão de root. O connect scan funciona sem privilégios e foi suficiente pra esse projeto.

## O que ainda quero adicionar

- [ ] UDP scan
- [ ] Detectar SO pelo TTL
- [ ] Relatório em HTML
- [ ] Integração com a API do Shodan

## Licença

MIT
