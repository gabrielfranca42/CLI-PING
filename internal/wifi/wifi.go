package wifi

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gabrifranca/cli_ping/internal/domain"
)

// WiFiService gerencia a listagem de redes WiFi e a localização do hashcat.
type WiFiService struct {
	hashcatPath string // Caminho cacheado do hashcat.exe após primeira detecção
}

// NewWiFiService cria uma nova instância do serviço WiFi.
func NewWiFiService() *WiFiService {
	return &WiFiService{}
}

// ScanNetworks lista as redes WiFi disponíveis no momento.
// No Windows usa `netsh wlan show networks mode=bssid`.
// No Linux usa `nmcli -t -f SSID,BSSID,SIGNAL,CHAN,SECURITY dev wifi list`.
func (w *WiFiService) ScanNetworks() ([]domain.WiFiNetwork, error) {
	if runtime.GOOS == "windows" {
		return w.scanWindows()
	}
	return w.scanLinux()
}

// scanWindows parseia a saída do netsh para extrair redes WiFi.
func (w *WiFiService) scanWindows() ([]domain.WiFiNetwork, error) {
	cmd := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("falha ao executar netsh: %w (verifique se o adaptador WiFi está ativo)", err)
	}

	return parseNetshOutput(string(output)), nil
}

// parseNetshOutput parseia a saída completa do netsh e retorna as redes encontradas.
func parseNetshOutput(output string) []domain.WiFiNetwork {
	var networks []domain.WiFiNetwork
	lines := strings.Split(output, "\n")

	var current domain.WiFiNetwork
	inBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SSID") && !strings.HasPrefix(line, "BSSID") {
			// Novo bloco de rede
			if inBlock && current.SSID != "" {
				networks = append(networks, current)
			}
			current = domain.WiFiNetwork{}
			inBlock = true

			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				current.SSID = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Tipo de rede") || strings.Contains(line, "Network type") {
			// Ignorar
		} else if strings.Contains(line, "Autentica") || strings.Contains(line, "Authentication") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				current.Auth = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Codifica") || strings.Contains(line, "Encryption") || strings.Contains(line, "Cifra") || strings.Contains(line, "Cipher") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				current.Encryption = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "BSSID") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				current.BSSID = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Sinal") || strings.Contains(line, "Signal") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				current.Signal = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Canal") || strings.Contains(line, "Channel") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				current.Channel = strings.TrimSpace(parts[1])
			}
		}
	}

	// Último bloco
	if inBlock && current.SSID != "" {
		networks = append(networks, current)
	}

	return networks
}

// scanLinux parseia a saída do nmcli para extrair redes WiFi.
func (w *WiFiService) scanLinux() ([]domain.WiFiNetwork, error) {
	cmd := exec.Command("nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("falha ao executar nmcli: %w", err)
	}

	var networks []domain.WiFiNetwork
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 5 {
			continue
		}

		networks = append(networks, domain.WiFiNetwork{
			SSID:    parts[0],
			BSSID:   strings.Join(parts[1:7], ":"), // BSSID tem ":"
			Signal:  parts[7] + "%",
			Channel: parts[8],
			Auth:    parts[9],
		})
	}

	return networks, nil
}

// FindHashcat procura o executável do hashcat em locais comuns do sistema.
// Retorna o caminho completo ou erro se não encontrar.
func (w *WiFiService) FindHashcat() (string, error) {
	// Se já encontrou antes, retorna o cache
	if w.hashcatPath != "" {
		if _, err := os.Stat(w.hashcatPath); err == nil {
			return w.hashcatPath, nil
		}
	}

	// Tenta encontrar no PATH do sistema
	if path, err := exec.LookPath("hashcat"); err == nil {
		w.hashcatPath = path
		return path, nil
	}
	if path, err := exec.LookPath("hashcat.exe"); err == nil {
		w.hashcatPath = path
		return path, nil
	}

	// Locais comuns onde o hashcat pode estar
	homeDir, _ := os.UserHomeDir()
	commonPaths := []string{
		// Downloads (onde o usuário extraiu)
		filepath.Join(homeDir, "Downloads", "hashcat-7.1.2", "hashcat-7.1.2", "hashcat.exe"),
		filepath.Join(homeDir, "Downloads", "hashcat-6.2.6", "hashcat.exe"),
		filepath.Join(homeDir, "Downloads", "hashcat", "hashcat.exe"),
		// Desktop
		filepath.Join(homeDir, "Desktop", "hashcat", "hashcat.exe"),
		// Program Files
		`C:\hashcat\hashcat.exe`,
		`C:\Program Files\hashcat\hashcat.exe`,
		`C:\Tools\hashcat\hashcat.exe`,
		// Linux
		"/usr/bin/hashcat",
		"/usr/local/bin/hashcat",
	}

	for _, p := range commonPaths {
		if _, err := os.Stat(p); err == nil {
			w.hashcatPath = p
			return p, nil
		}
	}

	return "", fmt.Errorf("hashcat não encontrado. Instale em https://hashcat.net/hashcat/ e adicione ao PATH ou informe o caminho manualmente")
}

// SetHashcatPath define manualmente o caminho do hashcat.
func (w *WiFiService) SetHashcatPath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("arquivo não encontrado: %s", path)
	}
	w.hashcatPath = path
	return nil
}

// GetHashcatPath retorna o caminho atual do hashcat (pode estar vazio).
func (w *WiFiService) GetHashcatPath() string {
	return w.hashcatPath
}
