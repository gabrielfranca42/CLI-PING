package osint

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type OSINTService struct {
	Providers []OSINTProvider
	ActiveIdx int
}

func NewOSINTService() *OSINTService {
	svc := &OSINTService{
		Providers: []OSINTProvider{
			NewCriminalIPProvider(),
			NewLeakIXProvider(),
		},
		ActiveIdx: 0, // Criminal IP default
	}
	svc.autoLoadKeys()
	return svc
}

func (s *OSINTService) autoLoadKeys() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := filepath.Join(home, ".ajin")

	for _, p := range s.Providers {
		keyName := strings.ToLower(strings.ReplaceAll(p.Name(), " ", ""))
		keyFile := filepath.Join(dir, keyName+".key")
		data, err := os.ReadFile(keyFile)
		if err == nil {
			key := strings.TrimSpace(string(data))
			if key != "" {
				p.SetAPIKey(key)
			}
		}
	}
}

func (s *OSINTService) SaveAPIKey(providerName, key string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ajin")
	os.MkdirAll(dir, 0700)

	keyName := strings.ToLower(strings.ReplaceAll(providerName, " ", ""))
	keyFile := filepath.Join(dir, keyName+".key")
	return os.WriteFile(keyFile, []byte(key), 0600)
}

func (s *OSINTService) ActiveProvider() OSINTProvider {
	return s.Providers[s.ActiveIdx]
}

func (s *OSINTService) ToggleProvider() {
	s.ActiveIdx = (s.ActiveIdx + 1) % len(s.Providers)
}

func (s *OSINTService) HostLookup(ip string) (*OSINTHostResult, error) {
	p := s.ActiveProvider()
	if p.RequiresAPIKey() && !p.HasAPIKey() {
		return nil, fmt.Errorf("provedor %s requer API Key", p.Name())
	}
	return p.HostLookup(ip)
}

func (s *OSINTService) Search(query string, page int) (*OSINTSearchResult, error) {
	p := s.ActiveProvider()
	if p.RequiresAPIKey() && !p.HasAPIKey() {
		return nil, fmt.Errorf("provedor %s requer API Key", p.Name())
	}
	return p.Search(query, page)
}

// ReverseDNS nativo usando Go (totalmente gratuito)
func (s *OSINTService) ReverseDNS(ips []string) map[string][]string {
	result := make(map[string][]string)
	for _, ip := range ips {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			result[ip] = names
		} else {
			result[ip] = []string{}
		}
	}
	return result
}
