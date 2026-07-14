# CLI-Ping 🏓

**CLI para verificar o status de serviços e endpoints HTTP/HTTPS.**

Ferramenta de linha de comando escrita em Go que realiza pings HTTP em endpoints, serviços e APIs, relatando seu status em tempo real. Além disso, conta com um **Sniffer de Rede Integrado** capaz de analisar tráfego de pacotes, realizar OS Fingerprinting (via TTL) e monitorar consultas DNS locais.

## Arquitetura

O projeto segue o padrão **MVC (Model-View-Controller)**:

```
CLI_PING/
├── main.go                         # Entry point
├── model/
│   └── ping_result.go              # Estruturas de dados (PingResult, PingOptions)
├── service/
│   ├── ping_service.go             # Lógica de negócio (HTTP requests, TLS check)
│   └── sniffer_service.go          # Sniffer de rede, OS Fingerprinting, DNS monitor
├── controller/
│   └── ping_controller.go          # Orquestração CLI, parsing de args, roteamento
├── view/
│   └── printer.go                  # Formatação de output (cores ANSI, tabelas, JSON)
├── go.mod
├── .gitignore
└── README.md
```

| Camada         | Responsabilidade                                   |
|----------------|---------------------------------------------------|
| **Model**      | Define as estruturas de dados (`PingResult`, `PingOptions`) |
| **Service**    | Executa HTTP requests, mede latência, intercepta pacotes (Sniffer) |
| **Controller** | Parseia argumentos CLI, roteia para os handlers e controla o Menu Interativo |
| **View**       | Formata e exibe resultados (cores, tabelas, JSON)  |

## Instalação

```bash
# Clone o repositório
git clone https://github.com/gabrifranca/cli-ping.git
cd cli-ping

# Build
go build -o cli-ping.exe .
```

## Uso

### Ping simples
```bash
cli-ping ping google.com
cli-ping ping https://my-app.onrender.com
```

### Ping em múltiplos endpoints
```bash
cli-ping ping google.com github.com api.example.com
```

### Ping repetido (monitoramento)
```bash
cli-ping ping -c 5 -i 2 api.example.com
```

### Saída JSON
```bash
cli-ping ping --json https://my-service.onrender.com
```

### Verificar certificado TLS
```bash
cli-ping check my-app.onrender.com
```

### Escuta Passiva (Network Sniffer)
Para utilizar a escuta de rede e visualizar tráfego, identificar Sistemas Operacionais via TTL e rastrear domínios visitados:
```bash
# Inicie o modo interativo (se implementado assim) ou via comando específico:
cli-ping sniffer
```
*(Nota: Para utilizar o sniffer no Windows, é necessário ter o Npcap instalado e rodar o terminal como Administrador)*

## Flags

| Flag                 | Descrição                              | Default |
|----------------------|----------------------------------------|---------|
| `-t`, `--timeout`    | Timeout da requisição em segundos      | 10      |
| `-c`, `--count`      | Número de pings a enviar               | 1       |
| `-i`, `--interval`   | Intervalo entre pings em segundos      | 1       |
| `-m`, `--method`     | Método HTTP (GET, HEAD, POST...)       | GET     |
| `--no-follow`        | Não seguir redirects HTTP              | false   |
| `--json`             | Output em formato JSON                 | false   |
| `--headers`          | Mostrar headers da resposta            | false   |

## Exemplo de Output

```
  ┌─────────────────────────────────────────────────┐
  │ https://google.com                              │
  ├─────────────────────────────────────────────────┤
  │  Status:      UP                                │
  │  HTTP Code:   200                                │
  │  Latency:     234ms                              │
  │  Alive:       ✓ Online                           │
  │  TLS:         ✓ Valid (expires 2026-09-14)       │
  │  Checked at:  19:11:59 13/07/2026                │
  └─────────────────────────────────────────────────┘
```

## Tecnologias

- **Go 1.26+**
- **`net/http`** & **`crypto/tls`** — Requisições HTTP e Verificação de certificados TLS
- **`github.com/google/gopacket`** — Captura e análise profunda de pacotes (Deep Packet Inspection)
- **Npcap / libpcap** — Dependência de sistema para captura de rede
- **ANSI Colors** — Output colorido no terminal
