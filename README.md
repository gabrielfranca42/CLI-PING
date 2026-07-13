# CLI-Ping 🏓

**CLI para verificar o status de serviços e endpoints HTTP/HTTPS.**

Ferramenta de linha de comando escrita em Go que realiza pings HTTP em endpoints, serviços e APIs — incluindo serviços hospedados no Render, Vercel, Railway, etc. — e relata seu status em tempo real com output colorido.

## Arquitetura

O projeto segue o padrão **MVC (Model-View-Controller)**:

```
CLI_PING/
├── main.go                         # Entry point
├── model/
│   └── ping_result.go              # Estruturas de dados (PingResult, PingOptions)
├── service/
│   └── ping_service.go             # Lógica de negócio (HTTP requests, TLS check)
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
| **Model**      | Define as estruturas `PingResult` e `PingOptions`  |
| **Service**    | Executa HTTP requests, mede latência, verifica TLS |
| **Controller** | Parseia argumentos CLI e roteia para os handlers   |
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

- **Go 1.26+** — Sem dependências externas
- **`net/http`** — Requisições HTTP
- **`crypto/tls`** — Verificação de certificados TLS
- **ANSI Colors** — Output colorido no terminal
