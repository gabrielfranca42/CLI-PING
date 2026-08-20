package osint

// OSINTHostResult representa as informações consolidadas de um IP.
type OSINTHostResult struct {
	IP           string               `json:"ip"`
	Provider     string               `json:"provider"`
	Organization string               `json:"org"`
	Country      string               `json:"country"`
	City         string               `json:"city"`
	Services     []OSINTServicePort   `json:"services"`
	Vulns        []OSINTVulnerability `json:"vulns"`
	Hostnames    []string             `json:"hostnames"`
	Tags         []string             `json:"tags"`
	ScoreOutbound string              `json:"score_outbound"`
	SearchCount   int                 `json:"search_count"`
}

// OSINTServicePort representa um serviço rodando em uma porta específica.
type OSINTServicePort struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"` // "tcp", "udp"
	Service   string `json:"service"`   // "http", "ssh"
	Product   string `json:"product"`   // "nginx", "OpenSSH"
	Version   string `json:"version"`
	Banner    string `json:"banner"`
}

// OSINTVulnerability representa uma vulnerabilidade ou vazamento (CVE/Leak).
type OSINTVulnerability struct {
	ID          string `json:"id"`          // CVE-2021-1234 ou nome do Leak
	Description string `json:"description"` // Detalhes rápidos
	Severity    string `json:"severity"`    // High, Medium, Low
	CWEName     string `json:"cwe_name"`    // ex: "Out-of-bounds Read"
}

// OSINTSearchMatch representa um dispositivo encontrado na busca global.
type OSINTSearchMatch struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Product  string `json:"product"`
	Country  string `json:"country"`
	Banner   string `json:"banner"`
}

// OSINTSearchResult consolida resultados de buscas.
type OSINTSearchResult struct {
	Total   int                `json:"total"`
	Matches []OSINTSearchMatch `json:"matches"`
}

// OSINTProvider define os contratos que qualquer integração (CriminalIP, LeakIX) deve cumprir.
type OSINTProvider interface {
	Name() string
	RequiresAPIKey() bool
	HasAPIKey() bool
	SetAPIKey(key string)
	HostLookup(ip string) (*OSINTHostResult, error)
	Search(query string, page int) (*OSINTSearchResult, error)
}
