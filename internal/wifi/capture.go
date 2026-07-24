package wifi

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// CaptureResult armazena o resultado de uma captura de handshake.
type CaptureResult struct {
	PcapngFile  string // Caminho do arquivo .pcapng capturado
	Hc22000File string // Caminho do arquivo .hc22000 convertido
	Success     bool   // Se a captura e conversão foram bem-sucedidas
	Error       string // Mensagem de erro (se houver)
}

// CheckCaptureTools verifica se as ferramentas de captura estão instaladas.
// Retorna: hcxdumptoolPath, hcxpcapngtoolPath, erro
func CheckCaptureTools() (string, string, error) {
	if runtime.GOOS == "windows" {
		return "", "", fmt.Errorf("captura automática não disponível no Windows (requer modo monitor)")
	}

	dumptool, err := exec.LookPath("hcxdumptool")
	if err != nil {
		return "", "", fmt.Errorf("hcxdumptool não encontrado. Instale com: sudo apt install hcxdumptool")
	}

	pcapngtool, err := exec.LookPath("hcxpcapngtool")
	if err != nil {
		return dumptool, "", fmt.Errorf("hcxpcapngtool não encontrado. Instale com: sudo apt install hcxtools")
	}

	return dumptool, pcapngtool, nil
}

// ListPcapInterfaces lista as interfaces de rede disponíveis usando gopacket/pcap (Npcap/libpcap).
func ListPcapInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar interfaces pcap: %w", err)
	}
	return devices, nil
}

// RunCaptureGopacket escuta uma interface de rede usando Npcap e salva pacotes EAPOL (Handshake)
// diretamente em um arquivo .pcap. Funciona nativamente no Windows.
func RunCaptureGopacket(ctx context.Context, deviceName string, outputFile string, onOutput func(line string)) error {
	// Abre a interface em modo promíscuo
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("erro ao abrir interface %s: %w", deviceName, err)
	}
	defer handle.Close()

	// Filtro BPF para capturar apenas EAPOL (Handshake WPA)
	// ether proto 0x888e captura pacotes EAPOL em redes Ethernet/WiFi gerenciado (traduzido pelo Windows).
	err = handle.SetBPFFilter("ether proto 0x888e")
	if err != nil {
		return fmt.Errorf("erro ao configurar filtro BPF: %w", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("erro ao criar arquivo pcap: %w", err)
	}
	defer f.Close()

	// Inicializa o escritor PCAP
	pcapWriter := pcapgo.NewWriter(f)
	err = pcapWriter.WriteFileHeader(65536, handle.LinkType())
	if err != nil {
		return fmt.Errorf("erro ao escrever cabeçalho pcap: %w", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetsChan := packetSource.Packets()

	if onOutput != nil {
		onOutput(fmt.Sprintf("Escutando pacotes EAPOL na interface %s...", deviceName))
	}

	capturedCount := 0

	for {
		select {
		case <-ctx.Done():
			if onOutput != nil {
				onOutput(fmt.Sprintf("Captura encerrada. Total de pacotes EAPOL: %d", capturedCount))
			}
			return nil
		case packet, ok := <-packetsChan:
			if !ok {
				return fmt.Errorf("canal de pacotes fechado inesperadamente")
			}
			
			// Escreve no arquivo pcap
			err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				if onOutput != nil {
					onOutput(fmt.Sprintf("Erro ao gravar pacote: %v", err))
				}
				continue
			}

			capturedCount++
			
			// Extrai informações do pacote para exibir
			srcMAC := "Desconhecido"
			dstMAC := "Desconhecido"
			if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)
				srcMAC = eth.SrcMAC.String()
				dstMAC = eth.DstMAC.String()
			} else if dot11Layer := packet.Layer(layers.LayerTypeDot11); dot11Layer != nil {
				dot11, _ := dot11Layer.(*layers.Dot11)
				srcMAC = dot11.Address2.String()
				dstMAC = dot11.Address1.String()
			}

			if onOutput != nil {
				onOutput(fmt.Sprintf("Handshake Frame [#%d] capturado! (%s -> %s | %d bytes)", 
					capturedCount, srcMAC, dstMAC, len(packet.Data())))
			}
		}
	}
}

// ListMonitorInterfaces lista interfaces WiFi que suportam modo monitor (Linux).
func ListMonitorInterfaces() ([]string, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("listagem de interfaces de monitor só está disponível no Linux")
	}

	// Usa iw para listar interfaces wireless
	cmd := exec.Command("iw", "dev")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("falha ao listar interfaces: %w", err)
	}

	var interfaces []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			iface := strings.TrimPrefix(line, "Interface ")
			interfaces = append(interfaces, iface)
		}
	}

	return interfaces, nil
}

// RunCapture executa hcxdumptool para capturar pacotes WiFi com handshakes.
// O callback onOutput é chamado para cada linha da saída.
// O usuário deve cancelar o contexto (Ctrl+C) quando quiser parar a captura.
func RunCapture(ctx context.Context, iface string, outputFile string, onOutput func(line string)) error {
	dumptoolPath, err := exec.LookPath("hcxdumptool")
	if err != nil {
		return fmt.Errorf("hcxdumptool não encontrado: %w", err)
	}

	// hcxdumptool -i <interface> -o <output.pcapng> --active_beacon --enable_status=15
	cmd := exec.CommandContext(ctx, "sudo", dumptoolPath,
		"-i", iface,
		"-o", outputFile,
		"--active_beacon",
		"--enable_status=15",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("erro ao criar pipe stdout: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("erro ao iniciar hcxdumptool: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if onOutput != nil {
			onOutput(line)
		}
	}

	// Ignora erros de contexto cancelado (é o fluxo normal — Ctrl+C para parar)
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil // Cancelado pelo usuário — OK
	}
	return err
}

// ConvertPcapngToHc22000 converte um arquivo .pcapng capturado para o formato .hc22000 do hashcat.
// Retorna o caminho do arquivo .hc22000 gerado e informações sobre os handshakes encontrados.
func ConvertPcapngToHc22000(pcapngFile string) (string, string, error) {
	pcapngtoolPath, err := exec.LookPath("hcxpcapngtool")
	if err != nil {
		return "", "", fmt.Errorf("hcxpcapngtool não encontrado: %w", err)
	}

	// Verifica se o arquivo .pcapng existe
	if _, err := os.Stat(pcapngFile); err != nil {
		return "", "", fmt.Errorf("arquivo não encontrado: %s", pcapngFile)
	}

	// Gera o nome do arquivo de saída
	baseName := strings.TrimSuffix(filepath.Base(pcapngFile), filepath.Ext(pcapngFile))
	outputDir := filepath.Dir(pcapngFile)
	hc22000File := filepath.Join(outputDir, baseName+".hc22000")

	// hcxpcapngtool -o <output.hc22000> <input.pcapng>
	cmd := exec.Command(pcapngtoolPath, "-o", hc22000File, pcapngFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", string(output), fmt.Errorf("erro ao converter: %w\nSaída: %s", err, string(output))
	}

	// Verifica se o arquivo foi gerado
	if _, err := os.Stat(hc22000File); err != nil {
		return "", string(output), fmt.Errorf("conversão concluída mas arquivo .hc22000 não foi gerado.\nIsso geralmente significa que nenhum handshake EAPOL/PMKID válido foi encontrado na captura.\nSaída: %s", string(output))
	}

	return hc22000File, string(output), nil
}

// GenerateDefaultCapturePath gera um caminho padrão para salvar a captura com timestamp.
func GenerateDefaultCapturePath(ext string) string {
	homeDir, _ := os.UserHomeDir()
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	return filepath.Join(homeDir, fmt.Sprintf("captura_%s.%s", timestamp, ext))
}

// GetCaptureInstructions retorna instruções detalhadas para captura manual do handshake.
// Útil para Windows ou quando as ferramentas não estão instaladas.
func GetCaptureInstructions() string {
	return `
╔══════════════════════════════════════════════════════════════════════╗
║               GUIA: CAPTURA DO 4-WAY HANDSHAKE                     ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  PRÉ-REQUISITOS:                                                     ║
║  • Adaptador WiFi com suporte a MODO MONITOR                        ║
║  • Linux (Kali, Ubuntu, Parrot, etc.)                                ║
║  • Ferramentas: hcxdumptool + hcxtools (hcxpcapngtool)              ║
║                                                                      ║
║  INSTALAÇÃO (Debian/Ubuntu/Kali):                                    ║
║  ┌──────────────────────────────────────────────┐                    ║
║  │  sudo apt update                              │                    ║
║  │  sudo apt install hcxdumptool hcxtools        │                    ║
║  └──────────────────────────────────────────────┘                    ║
║                                                                      ║
║  PASSO 1 — Identifique sua interface WiFi:                           ║
║  ┌──────────────────────────────────────────────┐                    ║
║  │  iw dev                                       │                    ║
║  │  # Procure por "Interface wlan0" ou similar   │                    ║
║  └──────────────────────────────────────────────┘                    ║
║                                                                      ║
║  PASSO 2 — Capture o tráfego (~60 a 120 segundos):                   ║
║  ┌──────────────────────────────────────────────────────────────┐    ║
║  │  sudo hcxdumptool -i wlan0 -o captura.pcapng --active_beacon │    ║
║  │  # Pressione Ctrl+C quando quiser parar                       │    ║
║  └──────────────────────────────────────────────────────────────┘    ║
║                                                                      ║
║  PASSO 3 — Converta para .hc22000 (formato do Hashcat):              ║
║  ┌──────────────────────────────────────────────────────────────┐    ║
║  │  hcxpcapngtool -o handshake.hc22000 captura.pcapng            │    ║
║  └──────────────────────────────────────────────────────────────┘    ║
║                                                                      ║
║  ⚠️  O arquivo .hc22000 gerado é o que você deve informar            ║
║     nas opções de Brute Force ou Dicionário deste programa.          ║
║                                                                      ║
║  ALTERNATIVA (WINDOWS):                                              ║
║  No Windows use o Wireshark com adaptador em modo monitor            ║
║  + WPA2 decryption, ou use um Live USB com Kali Linux.               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝`
}
