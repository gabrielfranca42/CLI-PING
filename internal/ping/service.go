package ping

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gabrifranca/cli_ping/internal/domain"
)

// PingService handles the business logic for pinging endpoints.
type PingService struct{}

// NewPingService é o construtor da camada de serviço de Ping.
// Retorna uma nova instância do serviço pronta para uso. instance.
func NewPingService() *PingService {
	return &PingService{}
}

// normalizeURL ensures the URL has a proper scheme.
func (s *PingService) normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	return rawURL
}

// Ping sends an HTTP request to the given URL and returns the result.
func (s *PingService) Ping(rawURL string, opts domain.PingOptions) domain.PingResult {
	url := s.normalizeURL(rawURL)

	result := domain.PingResult{
		URL:       url,
		Timestamp: time.Now(),
	}

	// Build HTTP client
	client := &http.Client{
		Timeout: opts.Timeout,
	}

	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// Create the request
	req, err := http.NewRequest(opts.Method, url, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		result.Status = "ERROR"
		return result
	}

	req.Header.Set("User-Agent", "CLI-Ping/1.0")

	// Execute the request and measure latency
	start := time.Now()
	resp, err := client.Do(req)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.Status = "DOWN"
		result.Alive = false
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Status = s.classifyStatus(resp.StatusCode)
	result.Alive = resp.StatusCode >= 200 && resp.StatusCode < 400

	// Check TLS certificate info
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		result.TLSValid = time.Now().Before(cert.NotAfter)
		result.TLSExpiry = cert.NotAfter
	}

	return result
}

// PingMultiple pings a list of URLs and returns all results.
func (s *PingService) PingMultiple(urls []string, opts domain.PingOptions) []domain.PingResult {
	results := make([]domain.PingResult, 0, len(urls))
	for _, url := range urls {
		results = append(results, s.Ping(url, opts))
	}
	return results
}

// PingRepeat pings a URL multiple times with a delay interval.
func (s *PingService) PingRepeat(rawURL string, opts domain.PingOptions) []domain.PingResult {
	results := make([]domain.PingResult, 0, opts.Count)
	for i := 0; i < opts.Count; i++ {
		results = append(results, s.Ping(rawURL, opts))
		if i < opts.Count-1 {
			time.Sleep(opts.Interval)
		}
	}
	return results
}

// CheckTLS performs a TLS handshake and returns certificate info.
func (s *PingService) CheckTLS(rawURL string, timeout time.Duration) domain.PingResult {
	url := s.normalizeURL(rawURL)
	result := domain.PingResult{
		URL:       url,
		Timestamp: time.Now(),
	}

	// Extract the host from the URL
	host := strings.TrimPrefix(url, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.Split(host, "/")[0]

	if !strings.Contains(host, ":") {
		host += ":443"
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		host,
		&tls.Config{InsecureSkipVerify: false},
	)

	if err != nil {
		result.Error = fmt.Sprintf("TLS handshake failed: %v", err)
		result.Status = "TLS_ERROR"
		result.TLSValid = false
		return result
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		result.TLSValid = time.Now().Before(cert.NotAfter)
		result.TLSExpiry = cert.NotAfter
		result.Status = "TLS_OK"
		if !result.TLSValid {
			result.Status = "TLS_EXPIRED"
		}
	}

	return result
}

// classifyStatus returns a human-readable status based on HTTP status code.
func (s *PingService) classifyStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "UP"
	case code >= 300 && code < 400:
		return "REDIRECT"
	case code >= 400 && code < 500:
		return "CLIENT_ERROR"
	case code >= 500:
		return "SERVER_ERROR"
	default:
		return "UNKNOWN"
	}
}
