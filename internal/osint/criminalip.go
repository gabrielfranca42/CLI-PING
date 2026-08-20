package osint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type CriminalIPProvider struct {
	apiKey     string
	httpClient *http.Client
}

func NewCriminalIPProvider() *CriminalIPProvider {
	return &CriminalIPProvider{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (p *CriminalIPProvider) Name() string {
	return "Criminal IP"
}

func (p *CriminalIPProvider) RequiresAPIKey() bool {
	return true
}

func (p *CriminalIPProvider) HasAPIKey() bool {
	return p.apiKey != ""
}

func (p *CriminalIPProvider) SetAPIKey(key string) {
	p.apiKey = key
}

func (p *CriminalIPProvider) doRequest(endpoint string) ([]byte, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("Criminal IP requer API Key. Configure na opção de Configurar API Keys")
	}

	req, err := http.NewRequest("GET", "https://api.criminalip.io/v1"+endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("x-api-key", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro na requisição Criminal IP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resposta: %w", err)
	}

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("API Key inválida ou cota esgotada (HTTP 403)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("erro HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (p *CriminalIPProvider) HostLookup(ip string) (*OSINTHostResult, error) {
	data, err := p.doRequest(fmt.Sprintf("/asset/ip/report?ip=%s", ip))
	if err != nil {
		return nil, err
	}

	// Estrutura parcial da resposta do Criminal IP
	var resp struct {
		IP struct {
			Score struct {
				Inbound  string `json:"inbound"`
				Outbound string `json:"outbound"`
			} `json:"score"`
		} `json:"ip"`
		Port struct {
			Data []struct {
				Port        int    `json:"open_port_no"`
				Protocol    string `json:"protocol"`
				AppName     string `json:"app_name"`
				AppVersion  string `json:"app_version"`
				Banner      string `json:"banner"`
			} `json:"data"`
		} `json:"port"`
		Vulnerability struct {
			Data []struct {
				CVEId      string `json:"cve_id"`
				Cvssv3Score float64 `json:"cvssv3_score"`
			} `json:"data"`
		} `json:"vulnerability"`
		Whois struct {
			Data []struct {
				Country string `json:"country"`
				OrgName string `json:"org_name"`
			} `json:"data"`
		} `json:"whois"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("erro ao parsear JSON Criminal IP: %w", err)
	}

	result := &OSINTHostResult{
		IP:       ip,
		Provider: "Criminal IP",
	}

	if len(resp.Whois.Data) > 0 {
		result.Country = resp.Whois.Data[0].Country
		result.Organization = resp.Whois.Data[0].OrgName
	}

	// Adiciona score como tag
	result.Tags = append(result.Tags, fmt.Sprintf("Score Inbound: %s", resp.IP.Score.Inbound))

	for _, portData := range resp.Port.Data {
		result.Services = append(result.Services, OSINTServicePort{
			Port:      portData.Port,
			Transport: portData.Protocol,
			Product:   portData.AppName,
			Version:   portData.AppVersion,
			Banner:    portData.Banner,
		})
	}

	for _, vuln := range resp.Vulnerability.Data {
		severity := "Low"
		if vuln.Cvssv3Score >= 9.0 {
			severity = "Critical"
		} else if vuln.Cvssv3Score >= 7.0 {
			severity = "High"
		} else if vuln.Cvssv3Score >= 4.0 {
			severity = "Medium"
		}
		
		result.Vulns = append(result.Vulns, OSINTVulnerability{
			ID:       vuln.CVEId,
			Severity: severity,
		})
	}

	return result, nil
}

func (p *CriminalIPProvider) Search(query string, page int) (*OSINTSearchResult, error) {
	// CriminalIP usa offset. Se page=1, offset=0.
	offset := (page - 1) * 10
	if offset < 0 {
		offset = 0
	}

	encodedQuery := url.QueryEscape(query)
	data, err := p.doRequest(fmt.Sprintf("/banner/search?query=%s&offset=%d", encodedQuery, offset))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Data struct {
			Count  int `json:"count"`
			Result []struct {
				IPAddress string `json:"ip_address"`
				OpenPortNo int   `json:"open_port_no"`
				AppName   string `json:"app_name"`
				Country   string `json:"country"`
				Banner    string `json:"banner"`
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("erro ao parsear JSON Criminal IP Search: %w", err)
	}

	result := &OSINTSearchResult{
		Total: resp.Data.Count,
	}

	for _, item := range resp.Data.Result {
		result.Matches = append(result.Matches, OSINTSearchMatch{
			IP:      item.IPAddress,
			Port:    item.OpenPortNo,
			Product: item.AppName,
			Country: item.Country,
			Banner:  item.Banner,
		})
	}

	return result, nil
}
