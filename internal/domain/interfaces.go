package domain

import (
	"context"
	"sync/atomic"
	"time"
)

// Pinger define os métodos obrigatórios para realizar testes de conectividade (Ping)
// e validação de certificados TLS. Qualquer serviço que implemente essa interface
// pode ser injetado no controlador principal (CLI).
type Pinger interface {
	// Ping envia requisições ICMP ou TCP/HTTP para testar se uma URL/IP está online.
	Ping(url string, opts PingOptions) PingResult
	// PingMultiple permite testar uma lista de domínios ou IPs simultaneamente.
	PingMultiple(urls []string, opts PingOptions) []PingResult
	// PingRepeat executa pings repetidos contra um mesmo alvo (útil para monitoramento contínuo).
	PingRepeat(url string, opts PingOptions) []PingResult
	// CheckTLS verifica a validade, emissor e data de expiração do certificado SSL/TLS de um domínio.
	CheckTLS(url string, timeout time.Duration) PingResult
}

// Scanner define os métodos responsáveis por varreduras de rede, testes de carga,
// e utilitários auxiliares (como DNS Lookup e Decode de JWT).
type Scanner interface {
	// PortScan verifica se uma porta específica está aberta em um host remoto.
	PortScan(host string, port int) bool
	// LocalPortScan varre um intervalo de portas na própria máquina local (localhost).
	LocalPortScan(startPort, endPort, concurrency int) []int
	// NetworkScan faz uma varredura do tipo "Ping Sweep" e "Port Scan" em toda a sub-rede.
	NetworkScan(baseIP string, ports []int, onFound func(host NetworkHost)) []NetworkHost
	// GetLocalIP descobre o endereço IP local (IPv4) ativo na máquina atual.
	GetLocalIP() (string, error)
	// GetNetworkBase calcula o endereço base da rede (ex: 192.168.0.1) a partir de um IP.
	GetNetworkBase(ip string) string
	// DNSLookup consulta os servidores DNS para encontrar os IPs associados a um domínio.
	DNSLookup(host string) ([]string, error)
	// LoadTest realiza um teste de estresse (DDoS/Stress Test benigno) contra uma URL alvo.
	LoadTest(url string, totalRequests, concurrency int) (int, int, time.Duration)
	// DecodeJWT decodifica as partes (Header e Payload) de um token JWT sem validar a assinatura.
	DecodeJWT(token string) (string, string, error)
	// DiagnoseNetwork executa um teste completo (Ping + Traceroute) para diagnosticar problemas de latência e rota.
	DiagnoseNetwork(target string) NetworkDiagnosticResult
}

// Sniffer define os métodos necessários para interagir com o tráfego de baixo nível da rede.
// Requer privilégios de Administrador/Root e biblioteca Npcap/libpcap instalada.
type Sniffer interface {
	// SniffNetwork inicia a escuta passiva da rede em modo promíscuo.
	// O parâmetro 'ctx' é usado para interromper a escuta graciosamente quando o usuário desejar.
	SniffNetwork(ctx context.Context) error
	// ARPSpoofMitM executa o ataque ativo de envenenamento ARP contra um IP alvo.
	// O parâmetro showLogs controla a exibição em tempo real dos logs no terminal.
	// Ao encerrar (ctx cancelado), gera automaticamente o log_ip.txt.
	ARPSpoofMitM(ctx context.Context, targetIP, manualMAC string, showLogs *atomic.Bool) error
}

// Reporter define o contrato para a geração de relatórios de rede.
// Qualquer módulo que precise gerar um log final ou exportar dados deve implementar isto.
type Reporter interface {
	// SaveReport escreve o conteúdo gerado em um arquivo físico no disco.
	SaveReport(filename, content string) error
}

// WebPentester define os métodos para pentest em aplicações web SSR.
type WebPentester interface {
	// Recon faz reconhecimento inicial do alvo: extrai headers, tecnologias, tokens e cookies.
	Recon(target WebPentestTarget) (WebPentestResult, error)
	// ExtractToken faz GET na página e extrai o valor atual do token de segurança (ssvtoken, __VIEWSTATE, etc.)
	ExtractToken(target WebPentestTarget) (string, []string, error)
	// TestLogin simula um POST de login com credenciais e token, analisando a resposta.
	TestLogin(target WebPentestTarget, login string, token string, cookies []string) (WebPentestResult, error)
	// FuzzField executa fuzzing automatizado em um campo do formulário, com rate limiting.
	FuzzField(config WebFuzzConfig, onResult func(WebPentestResult)) []WebPentestResult
	// AnalyzeHeaders inspeciona os headers de resposta em busca de problemas de segurança.
	AnalyzeHeaders(target WebPentestTarget) (map[string]string, []string)
}
