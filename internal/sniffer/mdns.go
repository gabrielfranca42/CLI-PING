package sniffer

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SendMDNSDiscovery envia uma consulta mDNS ativa para a rede local pedindo informações sobre todos os serviços
func (s *SnifferService) SendMDNSDiscovery(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP net.IP) error {
	// Endereços Multicast Padrão mDNS
	dstMAC, _ := net.ParseMAC("01:00:5e:00:00:fb") // IPv4 Multicast MAC para mDNS
	dstIP := net.ParseIP("224.0.0.251")            // IPv4 Multicast IP para mDNS

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      255, // mDNS exige TTL 255
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(5353),
		DstPort: layers.UDPPort(5353),
	}
	udp.SetNetworkLayerForChecksum(&ipv4)

	// Construindo a payload mDNS bruta para buscar TODOS os serviços (_services._dns-sd._udp.local)
	// Transaction ID: 0x0000
	// Flags: 0x0000 (Standard query)
	// Questions: 1
	// Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
	// Query: _services._dns-sd._udp.local (Type PTR, Class IN)
	dnsPayload := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // Flags
		0x00, 0x01, // 1 Question
		0x00, 0x00, // 0 Answers
		0x00, 0x00, // 0 Authority
		0x00, 0x00, // 0 Additional
		// Nome: _services._dns-sd._udp.local
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,       // Terminador nulo
		0x00, 0x0c, // Type: PTR (12)
		0x00, 0x01, // Class: IN (1)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &udp, gopacket.Payload(dnsPayload)); err != nil {
		return err
	}

	// Dispara 3 vezes para garantir a entrega (UDP)
	for i := 0; i < 3; i++ {
		_ = handle.WritePacketData(buf.Bytes())
		time.Sleep(50 * time.Millisecond)
	}

	return nil
}
