package service

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	manuf "github.com/timest/gomanuf"
)

type SnifferService struct{}

func NewSnifferService() *SnifferService {
	return &SnifferService{}
}

// Estrutura para armazenar dados e gerar um relatório ao final
type SnifferLogs struct {
	TotalPackets     int
	TotalBytes       int
	DiscoveredHosts  map[string]string            // Mapeamento de IP para Endereço MAC
	DNSQueries       map[string]map[string]int    // Domínio -> IP Solicitante -> Contagem
	TCPFlagsCounter  map[string]int               // Contagem de Flags TCP ("SYN", "FIN", etc.)
	SuspiciousIPs    map[string]int               // Contagem de pacotes suspeitos por IP (Ex: potenciais SYN Scans)
	ProtocolsCounter map[string]int               // Estatísticas de protocolos trafegados
	HostTTL          map[string]uint8             // TTL observado por IP (para OS Fingerprinting)
	HostOSByDNS      map[string]string            // OS detectado por Captive Portal DNS (IP -> "iOS/macOS", "Android", etc.)
}

// Domínios de Captive Portal conhecidos para detecção de SO
var captivePortalDomains = map[string]string{
	// Apple (iOS / macOS)
	"captive.apple.com":                        "iOS/macOS (Apple)",
	"www.apple.com":                             "iOS/macOS (Apple)",
	"gsp1.apple.com":                            "iOS/macOS (Apple)",
	"www.icloud.com":                            "iOS/macOS (Apple)",
	"configuration.apple.com":                   "iOS/macOS (Apple)",
	"gs-loc.apple.com":                          "iOS/macOS (Apple)",
	"init.push.apple.com":                       "iOS/macOS (Apple)",
	"courier.push.apple.com":                    "iOS/macOS (Apple)",
	// Android / Google
	"connectivitycheck.gstatic.com":              "Android (Google)",
	"connectivitycheck.android.com":              "Android (Google)",
	"clients3.google.com":                        "Android (Google)",
	"play.googleapis.com":                        "Android (Google)",
	"www.google.com":                             "Android (Google)",
	// Samsung (Android)
	"d.comenrz.net":                              "Android (Samsung)",
	"samsungcloudsolution.com":                   "Android (Samsung)",
	"samsungcloudsolution.net":                   "Android (Samsung)",
	"config.samsungads.com":                      "Android (Samsung)",
	// Microsoft Windows
	"www.msftconnecttest.com":                    "Windows (Microsoft)",
	"www.msftncsi.com":                           "Windows (Microsoft)",
	"dns.msftncsi.com":                           "Windows (Microsoft)",
	"ipv6.msftconnecttest.com":                   "Windows (Microsoft)",
	"settings-win.data.microsoft.com":            "Windows (Microsoft)",
	// Linux
	"nmcheck.gnome.org":                          "Linux (GNOME)",
	"network-test.debian.org":                    "Linux (Debian)",
	"detectportal.firefox.com":                   "Linux/Firefox",
}

func NewSnifferLogs() *SnifferLogs {
	return &SnifferLogs{
		DiscoveredHosts:  make(map[string]string),
		DNSQueries:       make(map[string]map[string]int),
		TCPFlagsCounter:  make(map[string]int),
		SuspiciousIPs:    make(map[string]int),
		ProtocolsCounter: make(map[string]int),
		HostTTL:          make(map[string]uint8),
		HostOSByDNS:      make(map[string]string),
	}
}

func (s *SnifferService) SniffNetwork(stopCh chan struct{}) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("Erro ao buscar interfaces (Verifique se o Npcap está instalado e rodando como Adm):", err)
		return
	}

	if len(devices) == 0 {
		log.Println("Nenhuma interface encontrada.")
		return
	}

	// Busca a primeira interface válida (IPv4, não-loopback e não-APIPA)
	var deviceName string
	var deviceDesc string
	var deviceIP string
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			ip := addr.IP.String()
			if ip != "127.0.0.1" && !strings.HasPrefix(ip, "169.254.") && addr.IP.To4() != nil {
				deviceName = dev.Name
				deviceDesc = dev.Description
				deviceIP = ip
				break
			}
		}
		if deviceName != "" {
			break
		}
	}
	if deviceName == "" {
		deviceName = devices[0].Name // Fallback
		deviceDesc = devices[0].Description
	}

	fmt.Printf("\n  [*] Iniciando escuta passiva...\n")
	fmt.Printf("      Interface: %s\n", deviceDesc)
	fmt.Printf("      IP Local: %s\n", deviceIP)

	// Abre a interface. Modo promíscuo é TRUE.
	handle, err := pcap.OpenLive(deviceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		log.Println("  [-] Erro ao abrir dispositivo:", err)
		return
	}
	defer handle.Close()

	// Recupera MAC e CIDR para a varredura ativa
	srcMAC, cidr := s.getInterfaceDetails(deviceIP)
	if srcMAC != nil && cidr != "" {
		fmt.Printf("  [*] Iniciando Varredura ARP Ativa em %s (Background)...\n", cidr)
		go s.ActiveARPSweep(deviceName, srcMAC, net.ParseIP(deviceIP), cidr)
	}

	fmt.Println("  [*] Escutando todo o tráfego da rede (Modo Promíscuo)...")
	fmt.Println("  [!] Pressione ENTER para encerrar a captura e gerar o RELATÓRIO DE ANÁLISE.")

	// Inicializa o nosso coletor de logs
	logs := NewSnifferLogs()

	for {
		select {
		case <-stopCh:
			fmt.Println("\n  [*] Escuta passiva finalizada. Processando dados analisados...")
			s.analyzeLogs(logs)
			return
		default:
			data, _, err := handle.ReadPacketData()
			if err != nil {
				continue // Provavelmente timeout do ReadPacketData, continua tentando
			}

			packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)
			
			// Incrementa estatísticas gerais
			logs.TotalPackets++
			logs.TotalBytes += len(data)

			var srcIP, dstIP string
			var srcMAC string
			var srcPort, dstPort string
			var protocol string = "Desconhecido"
			var extraInfo string
			var ttl uint8

			// 1. Camada Ethernet (Captura de Endereços MAC)
			if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)
				srcMAC = eth.SrcMAC.String()
				protocol = "Ethernet"
			}

			// 2. Camada ARP (Excelente para Mapeamento Passivo de Rede e detectar Spoofing)
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp, _ := arpLayer.(*layers.ARP)
				srcIP = net.IP(arp.SourceProtAddress).String()
				dstIP = net.IP(arp.DstProtAddress).String()
				
				// Ignora tráfego do nosso próprio IP
				if srcIP == deviceIP || dstIP == deviceIP {
					continue
				}

				protocol = "ARP"
				logs.DiscoveredHosts[srcIP] = srcMAC
				extraInfo = "Protocolo de Resolução de Endereços (ARP)"
			}

			// 3. Camada de Rede (IPv4/IPv6)
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				srcIP = netLayer.NetworkFlow().Src().String()
				dstIP = netLayer.NetworkFlow().Dst().String()
				protocol = netLayer.LayerType().String()

				// Filtro para ignorar IP ruidoso (Broadcast local) e a própria máquina
				if srcIP == "172.26.33.255" || dstIP == "172.26.33.255" || srcIP == deviceIP || dstIP == deviceIP {
					continue
				}

				// Extrai o TTL para OS Fingerprinting e armazena por IP
				if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
					ipv4, _ := ipv4Layer.(*layers.IPv4)
					ttl = ipv4.TTL
					if srcIP != "" && ttl > 0 {
						logs.HostTTL[srcIP] = ttl
					}
				}
				
				// Associa IP ao MAC descoberto
				if srcIP != "" && srcMAC != "" {
					logs.DiscoveredHosts[srcIP] = srcMAC
				}
			}

			// 4. Camada ICMP (Ping, Traceroute, Unreachable)
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				protocol = "ICMP"
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				extraInfo = fmt.Sprintf("Tipo: %d, Código: %d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
			}

			// 5. Camada de Transporte (TCP/UDP e Flags TCP)
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				protocol = transportLayer.LayerType().String()
				srcPort = transportLayer.TransportFlow().Src().String()
				dstPort = transportLayer.TransportFlow().Dst().String()

				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					var flags []string
					if tcp.SYN { flags = append(flags, "SYN"); logs.TCPFlagsCounter["SYN"]++ }
					if tcp.ACK { flags = append(flags, "ACK"); logs.TCPFlagsCounter["ACK"]++ }
					if tcp.FIN { flags = append(flags, "FIN"); logs.TCPFlagsCounter["FIN"]++ }
					if tcp.RST { flags = append(flags, "RST"); logs.TCPFlagsCounter["RST"]++ }
					if tcp.PSH { flags = append(flags, "PSH"); logs.TCPFlagsCounter["PSH"]++ }
					if tcp.URG { flags = append(flags, "URG"); logs.TCPFlagsCounter["URG"]++ }
					
					if len(flags) > 0 {
						extraInfo += fmt.Sprintf("[Flags: %s] ", strings.Join(flags, ","))
					}

					// Heurística de Segurança: Detecta possível SYN Scan (Muitos pacotes SYN sem ACK)
					if tcp.SYN && !tcp.ACK {
						logs.SuspiciousIPs[srcIP]++
					}
				}
			}

			// 6. Camada de Aplicação (Consultas DNS / Monitoramento de acessos)
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				if dns.OpCode == layers.DNSOpCodeQuery && len(dns.Questions) > 0 {
					dnsQuery := string(dns.Questions[0].Name)
					extraInfo += fmt.Sprintf("[Consulta DNS: %s] ", dnsQuery)
					
					// Verifica se o mapa interno para este domínio já existe
					if logs.DNSQueries[dnsQuery] == nil {
						logs.DNSQueries[dnsQuery] = make(map[string]int)
					}
					// Incrementa a contagem para o IP de origem específico
					logs.DNSQueries[dnsQuery][srcIP]++

					// Técnica 3: Detecção de OS via Captive Portal DNS
					dnsLower := strings.ToLower(dnsQuery)
					if detectedOS, match := captivePortalDomains[dnsLower]; match {
						if srcIP != "" {
							logs.HostOSByDNS[srcIP] = detectedOS
						}
					}
				}
			}

			// Identificando TLS/SSL rudimentarmente (Trafego HTTPS Criptografado)
			if (dstPort == "443" || srcPort == "443") && packet.ApplicationLayer() != nil {
				appPayload := packet.ApplicationLayer().Payload()
				if len(appPayload) > 0 && appPayload[0] == 0x16 {
					extraInfo += "[Dados TLS/SSL Criptografados] "
				}
			}

			// Registra protocolo nas estatísticas
			logs.ProtocolsCounter[protocol]++

			// Formatação Visual em tempo real
			portInfoSrc, portInfoDst := "", ""
			if srcPort != "" { portInfoSrc = ":" + srcPort }
			if dstPort != "" { portInfoDst = ":" + dstPort }

			ttlInfo, macInfo := "", ""
			if ttl > 0 { ttlInfo = fmt.Sprintf("[TTL:%d] ", ttl) }
			if srcMAC != "" {
				vendor := manuf.Search(srcMAC)
				if vendor != "" {
					macInfo = fmt.Sprintf("[%s|%s] ", srcMAC, vendor)
				} else {
					macInfo = fmt.Sprintf("[%s] ", srcMAC)
				}
			}

			fmt.Printf("  [>] %s%s%s -> %s%s [%s] %s%s\n", macInfo, srcIP, portInfoSrc, dstIP, portInfoDst, protocol, ttlInfo, extraInfo)
		}
	}
}

// analyzeLogs pega a estrutura preenchida durante a captura e emite um relatório analítico
func (s *SnifferService) analyzeLogs(logs *SnifferLogs) {
	var sb strings.Builder

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("                   RELATÓRIO DE ANÁLISE DE TRÁFEGO PASSIVO               \n")
	sb.WriteString("=========================================================================\n")
	sb.WriteString(fmt.Sprintf("  Volume Analisado: %d Pacotes | Tamanho Total: %.2f KB\n", logs.TotalPackets, float64(logs.TotalBytes)/1024.0))
	
	sb.WriteString("\n  [+] Hosts Descobertos Fisicamente (Mapeamento IP -> MAC):\n")
	if len(logs.DiscoveredHosts) > 0 {
		for ip, mac := range logs.DiscoveredHosts {
			if ip != "" && mac != "" {
				vendor := manuf.Search(mac)
				if vendor == "" { vendor = "Desconhecido" }
				sb.WriteString(fmt.Sprintf("      - IP: %-15s | MAC: %-17s | Fabricante: %s\n", ip, mac, vendor))
			}
		}
	} else {
		sb.WriteString("      Nenhum mapeamento IP/MAC encontrado na captura.\n")
	}

	sb.WriteString("\n  [+] Distribuição de Protocolos:\n")
	if len(logs.ProtocolsCounter) > 0 {
		for proto, count := range logs.ProtocolsCounter {
			sb.WriteString(fmt.Sprintf("      - %-10s: %d pacotes\n", proto, count))
		}
	} else {
		sb.WriteString("      Nenhum protocolo reconhecido.\n")
	}

	sb.WriteString("\n  [+] Rastreador de Acessos DNS (Quem acessou o quê):\n")
	if len(logs.DNSQueries) > 0 {
		for domain, ipCounts := range logs.DNSQueries {
			sb.WriteString(fmt.Sprintf("      - Domínio: %s\n", domain))
			for ip, count := range ipCounts {
				// Tenta buscar o MAC do IP, se conhecermos
				macStr := ""
				if mac, exists := logs.DiscoveredHosts[ip]; exists && mac != "" {
					vendor := manuf.Search(mac)
					if vendor == "" { vendor = "Desconhecido" }
					macStr = fmt.Sprintf(" [MAC: %s | Fab: %s]", mac, vendor)
				}
				sb.WriteString(fmt.Sprintf("          -> Requisitado por IP: %-15s %s (%d vezes)\n", ip, macStr, count))
			}
		}
	} else {
		sb.WriteString("      Nenhuma consulta DNS interceptada.\n")
	}

	sb.WriteString("\n  [+] Estatísticas de Conexões TCP (Flags):\n")
	for flag, count := range logs.TCPFlagsCounter {
		sb.WriteString(fmt.Sprintf("      - %s: %d ocorrências\n", flag, count))
	}

	// Seção de OS Fingerprinting (Técnicas 3 e 4 combinadas)
	sb.WriteString("\n  [+] OS Fingerprinting (Identificação de Dispositivos Desconhecidos):\n")
	
	// Coleta todos os IPs únicos que temos alguma informação de OS
	allIPs := make(map[string]bool)
	for ip := range logs.HostOSByDNS {
		allIPs[ip] = true
	}
	for ip := range logs.HostTTL {
		allIPs[ip] = true
	}

	if len(allIPs) > 0 {
		for ip := range allIPs {
			var osDNS, osTTL string
			var ttlVal uint8

			// Técnica 3: OS via DNS Captive Portal
			if os, exists := logs.HostOSByDNS[ip]; exists {
				osDNS = os
			}

			// Técnica 4: OS via TTL Fingerprinting
			if t, exists := logs.HostTTL[ip]; exists {
				ttlVal = t
				switch {
				case t >= 1 && t <= 64:
					osTTL = "Linux/Android/iOS/macOS (TTL base 64)"
				case t >= 65 && t <= 128:
					osTTL = "Windows (TTL base 128)"
				case t >= 129 && t <= 255:
					osTTL = "Roteador/Switch/Equipamento de Rede (TTL base 255)"
				}
			}

			// Decide o veredito final (DNS tem prioridade, é mais preciso)
			veredito := "Indeterminado"
			metodo := ""
			if osDNS != "" {
				veredito = osDNS
				metodo = "DNS Captive Portal"
			} else if osTTL != "" {
				veredito = osTTL
				metodo = "TTL Fingerprint"
			}

			if veredito == "Indeterminado" {
				continue
			}

			// Complementa com MAC se disponível
			macStr := ""
			if mac, exists := logs.DiscoveredHosts[ip]; exists && mac != "" {
				vendor := manuf.Search(mac)
				if vendor == "" {
					vendor = "MAC Randomizado"
				}
				macStr = fmt.Sprintf(" | MAC: %s (%s)", mac, vendor)
			}

			ttlStr := ""
			if ttlVal > 0 {
				ttlStr = fmt.Sprintf(" | TTL: %d", ttlVal)
			}

			sb.WriteString(fmt.Sprintf("      - IP: %-15s | SO: %-30s | Método: %s%s%s\n", ip, veredito, metodo, ttlStr, macStr))
		}
	} else {
		sb.WriteString("      Nenhuma impressão digital de SO capturada nesta sessão.\n")
	}

	sb.WriteString("\n  [!] Análise Heurística de Segurança:\n")
	hasAlerts := false
	for ip, synCount := range logs.SuspiciousIPs {
		// Threshold: se houver mais de 5 tentativas de SYN a partir de um IP (rudimentar, mas ilustrativo)
		if synCount > 5 { 
			sb.WriteString(fmt.Sprintf("      [ALERTA] IP %s gerou %d pacotes SYN. Possível varredura de portas (SYN Flood / Scan)!\n", ip, synCount))
			hasAlerts = true
		}
	}
	if !hasAlerts {
		sb.WriteString("      Nenhum tráfego suspeito evidente (baseado em anomalias de handshake) foi detectado.\n")
	}
	
	sb.WriteString("=========================================================================\n\n")

	reportContent := sb.String()

	// 1. Imprime no console para o usuário ver
	fmt.Print(reportContent)

	// 2. Salva em um arquivo .txt
	filename := fmt.Sprintf("sniffer_report_%s.txt", time.Now().Format("20060102_150405"))
	err := os.WriteFile(filename, []byte(reportContent), 0644)
	if err != nil {
		fmt.Printf("  [-] Erro ao salvar o relatório no arquivo: %v\n", err)
	} else {
		fmt.Printf("  [+] Relatório salvo com sucesso no arquivo: %s\n", filename)
	}
}

// getInterfaceDetails busca o MAC e o CIDR baseados no IP descoberto
func (s *SnifferService) getInterfaceDetails(targetIP string) (net.HardwareAddr, string) {
	ifaces, err := net.Interfaces()
	if err != nil { return nil, "" }
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil { continue }
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.String() == targetIP {
					return iface.HardwareAddr, ipnet.String()
				}
			}
		}
	}
	return nil, ""
}

// ActiveARPSweep varre uma sub-rede enviando ARP Requests para cada IP.
func (s *SnifferService) ActiveARPSweep(deviceName string, srcMAC net.HardwareAddr, srcIP net.IP, cidr string) {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return
	}
	defer handle.Close()

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	ips := s.generateIPList(ipNet)
	
	for _, targetIP := range ips {
		if targetIP.Equal(ip) || targetIP.Equal(s.broadcastIP(ipNet)) {
			continue
		}

		_ = s.sendARPRequest(handle, srcMAC, srcIP, targetIP)
		time.Sleep(1 * time.Millisecond) // Evita DoS no switch
	}
}

// sendARPRequest constrói e injeta o pacote ARP na rede
func (s *SnifferService) sendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	return handle.WritePacketData(buf.Bytes())
}

func (s *SnifferService) generateIPList(ipNet *net.IPNet) []net.IP {
	var ips []net.IP
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); s.incIP(ip) {
		dup := make(net.IP, len(ip))
		copy(dup, ip)
		ips = append(ips, dup)
	}
	return ips
}

func (s *SnifferService) incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (s *SnifferService) broadcastIP(n *net.IPNet) net.IP {
	var broadcast net.IP
	if len(n.IP) == 4 {
		broadcast = make(net.IP, 4)
	} else {
		broadcast = make(net.IP, 16)
	}
	for i := range broadcast {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}
