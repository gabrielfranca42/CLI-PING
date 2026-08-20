package osint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type LeakIXProvider struct {
	apiKey     string
	httpClient *http.Client
}

func NewLeakIXProvider() *LeakIXProvider {
	return &LeakIXProvider{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (p *LeakIXProvider) Name() string {
	return "LeakIX"
}

func (p *LeakIXProvider) RequiresAPIKey() bool {
	return false // LeakIX funciona bem sem API key para buscas básicas
}

func (p *LeakIXProvider) HasAPIKey() bool {
	return p.apiKey != ""
}

func (p *LeakIXProvider) SetAPIKey(key string) {
	p.apiKey = key
}

func (p *LeakIXProvider) doRequest(endpoint string) ([]byte, error) {
	req, err := http.NewRequest("GET", "https://leakix.net"+endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	if p.apiKey != "" {
		req.Header.Add("api-key", p.apiKey)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro na requisição LeakIX: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resposta: %w", err)
	}

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("Rate limit atingido. Configure uma API Key do LeakIX para limites maiores")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("erro HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (p *LeakIXProvider) HostLookup(ip string) (*OSINTHostResult, error) {
	data, err := p.doRequest(fmt.Sprintf("/host/%s", ip))
	if err != nil {
		return nil, err
	}

	// Estrutura parcial da resposta do LeakIX
	var resp struct {
		IP       string `json:"ip"`
		Services []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Software struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"software"`
		} `json:"services"`
		Leaks []struct {
			Plugin  string `json:"plugin"`
			Dataset string `json:"dataset"`
		} `json:"leaks"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("erro ao parsear JSON LeakIX: %w", err)
	}

	result := &OSINTHostResult{
		IP:       ip,
		Provider: "LeakIX",
	}

	for _, srv := range resp.Services {
		result.Services = append(result.Services, OSINTServicePort{
			Port:      srv.Port,
			Transport: srv.Protocol,
			Product:   srv.Software.Name,
			Version:   srv.Software.Version,
		})
	}

	for _, leak := range resp.Leaks {
		result.Vulns = append(result.Vulns, OSINTVulnerability{
			ID:          leak.Plugin,
			Description: leak.Dataset,
			Severity:    "High",
		})
	}

	return result, nil
}

func (p *LeakIXProvider) Search(query string, page int) (*OSINTSearchResult, error) {
	encodedQuery := url.QueryEscape(query)
	data, err := p.doRequest(fmt.Sprintf("/search?page=%d&q=%s&scope=service", page-1, encodedQuery))
	if err != nil {
		return nil, err
	}

	// A API retorna uma lista de resultados diretos
	var resp []struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Software struct {
			Name string `json:"name"`
		} `json:"software"`
		Geo struct {
			CountryName string `json:"country_name"`
		} `json:"geoip"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("erro ao parsear JSON LeakIX Search: %w", err)
	}

	result := &OSINTSearchResult{
		Total: len(resp), // LeakIX pagination doesn't easily expose totals in array
	}

	for _, item := range resp {
		result.Matches = append(result.Matches, OSINTSearchMatch{
			IP:      item.IP,
			Port:    item.Port,
			Product: item.Software.Name,
			Country: item.Geo.CountryName,
		})
	}

	return result, nil
}
