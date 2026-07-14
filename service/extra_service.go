package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gabrifranca/cli_ping/model"
)

// CommonPorts lists the most common ports to scan during network discovery.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
	443, 445, 993, 995, 1433, 1723, 3306, 3389,
	5432, 5900, 6379, 8080, 8443, 27017,
}

// PortNames maps well-known port numbers to their service names.
var PortNames = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
	139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
	993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
	8443: "HTTPS-Alt", 27017: "MongoDB",
}

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

// 5. GetLocalIP returns the local IP address of this machine.
func (s *ExtraService) GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// 6. GetNetworkBase extracts the /24 base from an IP (e.g., "10.67.82.250" -> "10.67.82").
func (s *ExtraService) GetNetworkBase(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return strings.Join(parts[:3], ".")
}

// 7. NetworkScan scans all 254 hosts in a /24 network checking common ports.
func (s *ExtraService) NetworkScan(baseIP string, ports []int, onFound func(host model.NetworkHost)) []model.NetworkHost {
	var results []model.NetworkHost
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	for i := 1; i <= 254; i++ {
		ip := fmt.Sprintf("%s.%d", baseIP, i)
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			var openPorts []int
			for _, port := range ports {
				target := net.JoinHostPort(ip, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", target, 500*time.Millisecond)
				if err == nil {
					conn.Close()
					openPorts = append(openPorts, port)
				}
			}

			if len(openPorts) > 0 {
				host := model.NetworkHost{IP: ip, OpenPorts: openPorts}
				mu.Lock()
				results = append(results, host)
				mu.Unlock()
				if onFound != nil {
					onFound(host)
				}
			}
		}(ip)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		partsI := strings.Split(results[i].IP, ".")
		partsJ := strings.Split(results[j].IP, ".")
		lastI, _ := strconv.Atoi(partsI[3])
		lastJ, _ := strconv.Atoi(partsJ[3])
		return lastI < lastJ
	})

	return results
}

// 8. LocalPortScan scans a range of ports on localhost concurrently.
func (s *ExtraService) LocalPortScan(startPort, endPort, concurrency int) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", p), 400*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(openPorts)
	return openPorts
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
