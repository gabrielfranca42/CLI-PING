package domain

import "time"

// PingResult armazena o resultado detalhado de uma única verificação de ping ou conectividade.
// Usado para consolidar os dados de resposta de um endpoint remoto, seja ICMP ou HTTP.
type PingResult struct {
	URL        string        `json:"url"`                   // Endereço alvo testado (ex: google.com)
	StatusCode int           `json:"status_code"`           // Código de status HTTP retornado (ex: 200, 404)
	Status     string        `json:"status"`                // Descrição textual do status
	Latency    time.Duration `json:"latency"`               // Tempo de resposta (Latência/Ping)
	Alive      bool          `json:"alive"`                 // Indica se o alvo respondeu e está ativo
	Error      string        `json:"error,omitempty"`       // Detalhe de erro (se a requisição falhar)
	Timestamp  time.Time     `json:"timestamp"`             // Momento exato em que o teste foi realizado
	TLSValid   bool          `json:"tls_valid"`             // Indica se o certificado TLS/SSL é válido
	TLSExpiry  time.Time     `json:"tls_expiry,omitempty"`  // Data de expiração do certificado TLS/SSL
}

// PingOptions estrutura as configurações e parâmetros ajustáveis para uma requisição de ping.
// Permite personalizar o comportamento das verificações, como tempo limite e método HTTP.
type PingOptions struct {
	Timeout         time.Duration // Tempo máximo a aguardar por uma resposta (Timeout)
	Method          string        // Método HTTP a ser usado, caso o ping seja na camada 7 (ex: GET, HEAD)
	Count           int           // Quantidade de disparos a serem feitos (ex: 4 pings seguidos)
	Interval        time.Duration // Intervalo de pausa entre um disparo e outro (PingRepeat)
	FollowRedirects bool          // Se verdadeiro, a requisição seguirá redirecionamentos (HTTP 3xx)
	ShowHeaders     bool          // Se verdadeiro, exibirá os cabeçalhos recebidos na resposta
}

// DefaultPingOptions retorna uma configuração padrão segura para ser usada na maioria dos casos.
// É útil para evitar de instanciar a estrutura manualmente o tempo todo.
func DefaultPingOptions() PingOptions {
	return PingOptions{
		Timeout:         10 * time.Second, // Máximo de 10 segundos antes de desistir
		Method:          "GET",            // Requisição padrão é GET
		Count:           1,                // Por padrão testa apenas uma vez
		Interval:        1 * time.Second,  // Aguarda 1s entre tentativas, se houver
		FollowRedirects: true,             // Acompanha redirecionamentos para evitar falsos negativos
		ShowHeaders:     false,            // Mantém a saída limpa por padrão
	}
}

// NetworkHost armazena informações de um único dispositivo descoberto na rede local (LAN).
// Geralmente é preenchido pelo resultado de varreduras do tipo NetworkScan ou ARP Sweep.
type NetworkHost struct {
	IP        string `json:"ip"`         // Endereço IP local (IPv4) do dispositivo descoberto
	OpenPorts []int  `json:"open_ports"` // Lista de portas abertas (TCP) encontradas nesse IP
}

// WiFiNetwork armazena informações de uma rede WiFi detectada pelo scanner.
type WiFiNetwork struct {
	SSID       string // Nome da rede (ex: "MinhaRede_5G")
	BSSID      string // Endereço MAC do access point (ex: "AA:BB:CC:DD:EE:FF")
	Signal     string // Intensidade do sinal em porcentagem (ex: "85%")
	Channel    string // Canal da rede WiFi (ex: "6")
	Auth       string // Tipo de autenticação (ex: "WPA2-Personal")
	Encryption string // Tipo de cifra usada (ex: "CCMP")
}

// HashcatAttackMode define o modo de ataque do hashcat.
type HashcatAttackMode int

const (
	// HashcatBruteForce usa máscara para testar todas as combinações possíveis (-a 3)
	HashcatBruteForce HashcatAttackMode = 3
	// HashcatDictionary usa um arquivo de wordlist com senhas conhecidas (-a 0)
	HashcatDictionary HashcatAttackMode = 0
)

// HashcatCharset define quais tipos de caracteres serão usados na máscara de brute force.
type HashcatCharset struct {
	Digits   bool // ?d = 0-9
	Lower    bool // ?l = a-z
	Upper    bool // ?u = A-Z
	Special  bool // ?s = !@#$%^&*()...
	AllPrint bool // ?a = todos os caracteres printáveis (combina todos acima)
}

// HashcatConfig armazena a configuração completa para executar o hashcat.
type HashcatConfig struct {
	BinaryPath    string            // Caminho completo para o hashcat.exe
	HandshakeFile string            // Caminho do arquivo .hc22000 (handshake capturado)
	AttackMode    HashcatAttackMode // Modo de ataque (brute force ou dicionário)
	Charset       HashcatCharset    // Charset para brute force (ignorado em modo dicionário)
	MinLength     int               // Comprimento mínimo da senha (padrão: 8)
	MaxLength     int               // Comprimento máximo da senha (padrão: 16)
	WordlistPath  string            // Caminho do arquivo de wordlist (apenas modo dicionário)
	RulesFile     string            // Caminho de arquivo de regras (opcional, modo dicionário)
}

// HashcatResult armazena o resultado final do hashcat após execução.
type HashcatResult struct {
	Found       bool   // Se a senha foi encontrada
	Password    string // A senha encontrada (vazio se não encontrou)
	Speed       string // Velocidade reportada (ex: "350.0 kH/s")
	TimeElapsed string // Tempo total de execução
	Status      string // Status final ("Cracked", "Exhausted", "Running", "Error")
}
