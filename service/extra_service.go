package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ExtraService struct{}

func NewExtraService() *ExtraService {
	return &ExtraService{}
}

// 1. Port Scanner
func (s *ExtraService) PortScan(host string, port int) bool {
	target := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// 2. DNS Lookup
func (s *ExtraService) DNSLookup(host string) ([]string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, ip := range ips {
		results = append(results, ip.String())
	}
	return results, nil
}

// 3. Load Testing
func (s *ExtraService) LoadTest(url string, totalRequests int, concurrency int) (success int, failed int, totalTime time.Duration) {
	start := time.Now()
	var wg sync.WaitGroup
	ch := make(chan struct{}, totalRequests)

	for i := 0; i < totalRequests; i++ {
		ch <- struct{}{}
	}
	close(ch)

	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range ch {
				client := &http.Client{Timeout: 5 * time.Second}
				resp, err := client.Get(url)

				mu.Lock()
				if err != nil || resp.StatusCode >= 400 {
					failed++
				} else {
					success++
				}
				mu.Unlock()

				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
	totalTime = time.Since(start)
	return
}

// 4. JWT Decoder
func (s *ExtraService) DecodeJWT(token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("token JWT inválido")
	}

	header, err := decodeBase64Segment(parts[0])
	if err != nil {
		return "", "", err
	}

	payload, err := decodeBase64Segment(parts[1])
	if err != nil {
		return "", "", err
	}

	return header, payload, nil
}

func decodeBase64Segment(seg string) (string, error) {
	seg = strings.ReplaceAll(seg, "-", "+")
	seg = strings.ReplaceAll(seg, "_", "/")

	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}

	data, err := base64.StdEncoding.DecodeString(seg)
	if err != nil {
		return "", err
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return string(data), nil
	}

	prettyJSON, err := json.MarshalIndent(parsed, "", "  ")
	if err != nil {
		return string(data), nil
	}

	return string(prettyJSON), nil
}
