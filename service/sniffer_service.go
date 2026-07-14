package service

import (
	"fmt"
	"log"
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

	// Abre a interface. Modo promíscuo é TRUE conforme desejado pelo usuário.
	// Usamos um timeout de 100ms para podermos checar o stopCh no loop.
	handle, err := pcap.OpenLive(deviceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		log.Println("  [-] Erro ao abrir dispositivo:", err)
		return
	}
	defer handle.Close()

	fmt.Println("  [*] Escutando todo o tráfego da rede (Mini Wireshark)...")
	fmt.Println("  [!] Pressione ENTER para encerrar a captura e voltar ao menu.")

	for {
		select {
		case <-stopCh:
			fmt.Println("\n  [*] Escuta passiva finalizada.")
			return
		default:
			data, _, err := handle.ReadPacketData()
			if err != nil {
				continue // Provavelmente timeout do ReadPacketData, continua tentando
			}

			packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Default)
			
			var srcIP, dstIP string
			var srcPort, dstPort string
			var protocol string = "Desconhecido"

			var ttl uint8

			// Extrai a camada de Rede (Ex: IPv4, IPv6)
			if netLayer := packet.NetworkLayer(); netLayer != nil {
				srcIP = netLayer.NetworkFlow().Src().String()
				dstIP = netLayer.NetworkFlow().Dst().String()
				protocol = netLayer.LayerType().String()

				// Extrai o TTL para OS Fingerprinting (Auditoria Defensiva)
				if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
					ipv4, _ := ipv4Layer.(*layers.IPv4)
					ttl = ipv4.TTL
				}

			} else {
				// Ignora pacotes sem IP (como Spanning Tree, etc) para não sujar muito a tela, 
				// mas se quiser ver TUDO mesmo, pode remover esse continue.
				continue 
			}

			// Extrai a camada de Transporte (Ex: TCP, UDP)
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				protocol = transportLayer.LayerType().String()
				srcPort = transportLayer.TransportFlow().Src().String()
				dstPort = transportLayer.TransportFlow().Dst().String()
			}

			// Extrai a camada de Aplicação: DNS (Monitoramento de tráfego / Auditoria)
			var dnsQuery string
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				// Se for uma requisição de pergunta (Query) e tiver perguntas
				if dns.OpCode == layers.DNSOpCodeQuery && len(dns.Questions) > 0 {
					dnsQuery = string(dns.Questions[0].Name)
				}
			}

			// Formata a saída para o terminal (Mini Wireshark)
			portInfoSrc := ""
			portInfoDst := ""
			if srcPort != "" {
				portInfoSrc = ":" + srcPort
			}
			if dstPort != "" {
				portInfoDst = ":" + dstPort
			}

			extraInfo := ""
			if ttl > 0 {
				extraInfo += fmt.Sprintf(" [TTL:%d]", ttl)
			}
			if dnsQuery != "" {
				extraInfo += fmt.Sprintf(" [DNS Query: %s]", dnsQuery)
			}

			fmt.Printf("  [>] %s%s -> %s%s [%s]%s\n", srcIP, portInfoSrc, dstIP, portInfoDst, protocol, extraInfo)
		}
	}
}
