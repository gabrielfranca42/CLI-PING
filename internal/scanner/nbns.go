package scanner

import (
	"bytes"
	"net"
	"strings"
	"time"
)

// NBNSResult contém os dados extraídos de uma consulta NetBIOS ativa.
type NBNSResult struct {
	Hostname  string
	Username  string
	Workgroup string
}

// NBNSLookup envia uma requisição ativa NBSTAT (UDP porta 137) para um IP.
// É útil para descobrir o Hostname, Grupo de Trabalho e Usuário Logado de máquinas Windows
// na rede local sem a necessidade de credenciais ou bibliotecas SMB externas.
func (s *ExtraService) NBNSLookup(ip string) (*NBNSResult, error) {
	target := net.JoinHostPort(ip, "137")
	
	// Timeout curto para não travar a varredura se a máquina não responder
	conn, err := net.DialTimeout("udp", target, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	// Construindo pacote NetBIOS Name Service (NBSTAT Request)
	// Transaction ID: 0x13 0x37
	// Flags: 0x00 0x00
	// Questions: 1, Answer RRs: 0, Authority RRs: 0, Additional RRs: 0
	// Query Name: "*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" (Wildcard stat)
	// Query Type: NBSTAT (0x21)
	// Query Class: IN (0x01)
	packet := []byte{
		0x13, 0x37, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, // Query Name (encoded "*")
		0x00, 0x21, // Query Type: NBSTAT
		0x00, 0x01, // Query Class: IN
	}

	_, err = conn.Write(packet)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	// Parse da resposta NBNS
	return parseNBNSReply(buf[:n])
}

// parseNBNSReply processa os bytes crus da resposta NBNS e extrai os nomes
func parseNBNSReply(data []byte) (*NBNSResult, error) {
	if len(data) < 57 { // Tamanho mínimo de um cabeçalho de resposta NBSTAT válido
		return nil, nil
	}
	
	// O número de nomes está no offset 56
	numNames := int(data[56])
	if numNames == 0 {
		return nil, nil
	}
	
	result := &NBNSResult{}
	
	offset := 57
	for i := 0; i < numNames; i++ {
		if offset+18 > len(data) {
			break
		}
		
		nameBytes := data[offset : offset+15]
		name := strings.TrimSpace(string(bytes.TrimRight(nameBytes, "\x00 ")))
		
		nameType := data[offset+15]
		flags := data[offset+16] // Bit mais alto define Grupo/Unique
		
		isGroup := (flags & 0x80) != 0
		
		// Lógica de sufixos do NetBIOS:
		// <00> UNIQUE: Hostname (Workstation Service)
		// <00> GROUP:  Workgroup/Domínio
		// <03> UNIQUE: Messenger Service (geralmente é o nome do usuário logado)
		if nameType == 0x00 && !isGroup {
			if result.Hostname == "" {
				result.Hostname = name
			}
		} else if nameType == 0x00 && isGroup {
			if result.Workgroup == "" {
				result.Workgroup = name
			}
		} else if nameType == 0x03 && !isGroup {
			// Evitar que o hostname ou nomes internos sejam confundidos com username
			if name != result.Hostname && !strings.Contains(name, "$") && !strings.Contains(name, "IS~") {
				result.Username = name
			}
		}
		
		offset += 18
	}
	
	return result, nil
}
