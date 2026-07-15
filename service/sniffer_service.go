package service

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
}

func NewSnifferLogs() *SnifferLogs {
	return &SnifferLogs{
		DiscoveredHosts:  make(map[string]string),
		DNSQueries:       make(map[string]map[string]int),
		TCPFlagsCounter:  make(map[string]int),
		SuspiciousIPs:    make(map[string]int),
		ProtocolsCounter: make(map[string]int),
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

				// Extrai o TTL para OS Fingerprinting
				if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
					ipv4, _ := ipv4Layer.(*layers.IPv4)
					ttl = ipv4.TTL
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
			if srcMAC != "" { macInfo = fmt.Sprintf("[%s] ", srcMAC) }

			fmt.Printf("  [>] %s%s%s -> %s%s [%s] %s%s\n", macInfo, srcIP, portInfoSrc, dstIP, portInfoDst, protocol, ttlInfo, extraInfo)
		}
	}
}

// analyzeLogs pega a estrutura preenchida durante a captura e emite um relatório analítico
func (s *SnifferService) analyzeLogs(logs *SnifferLogs) {
	fmt.Println("\n=========================================================================")
	fmt.Println("                   RELATÓRIO DE ANÁLISE DE TRÁFEGO PASSIVO               ")
	fmt.Println("=========================================================================")
	fmt.Printf("  Volume Analisado: %d Pacotes | Tamanho Total: %.2f KB\n", logs.TotalPackets, float64(logs.TotalBytes)/1024.0)
	
	fmt.Println("\n  [+] Hosts Descobertos Fisicamente (Mapeamento IP -> MAC):")
	if len(logs.DiscoveredHosts) > 0 {
		for ip, mac := range logs.DiscoveredHosts {
			if ip != "" && mac != "" {
				fmt.Printf("      - IP: %-15s | MAC: %s\n", ip, mac)
			}
		}
	} else {
		fmt.Println("      Nenhum mapeamento IP/MAC encontrado na captura.")
	}

	fmt.Println("\n  [+] Distribuição de Protocolos:")
	if len(logs.ProtocolsCounter) > 0 {
		for proto, count := range logs.ProtocolsCounter {
			fmt.Printf("      - %-10s: %d pacotes\n", proto, count)
		}
	} else {
		fmt.Println("      Nenhum protocolo reconhecido.")
	}

	fmt.Println("\n  [+] Rastreador de Acessos DNS (Quem acessou o quê):")
	if len(logs.DNSQueries) > 0 {
		for domain, ipCounts := range logs.DNSQueries {
			fmt.Printf("      - Domínio: %s\n", domain)
			for ip, count := range ipCounts {
				// Tenta buscar o MAC do IP, se conhecermos
				macStr := ""
				if mac, exists := logs.DiscoveredHosts[ip]; exists && mac != "" {
					macStr = fmt.Sprintf(" [MAC: %s]", mac)
				}
				fmt.Printf("          -> Requisitado por IP: %-15s %s (%d vezes)\n", ip, macStr, count)
			}
		}
	} else {
		fmt.Println("      Nenhuma consulta DNS interceptada.")
	}

	fmt.Println("\n  [+] Estatísticas de Conexões TCP (Flags):")
	for flag, count := range logs.TCPFlagsCounter {
		fmt.Printf("      - %s: %d ocorrências\n", flag, count)
	}

	fmt.Println("\n  [!] Análise Heurística de Segurança:")
	hasAlerts := false
	for ip, synCount := range logs.SuspiciousIPs {
		// Threshold: se houver mais de 5 tentativas de SYN a partir de um IP (rudimentar, mas ilustrativo)
		if synCount > 5 { 
			fmt.Printf("      [ALERTA] IP %s gerou %d pacotes SYN. Possível varredura de portas (SYN Flood / Scan)!\n", ip, synCount)
			hasAlerts = true
		}
	}
	if !hasAlerts {
		fmt.Println("      Nenhum tráfego suspeito evidente (baseado em anomalias de handshake) foi detectado.")
	}
	
	fmt.Println("=========================================================================\n")
}
