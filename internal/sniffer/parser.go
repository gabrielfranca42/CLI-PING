package sniffer

import (
	"strings"
)

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

	// Index comeÃ§a em: 5 (inÃ­cio do handshake payload) + 4 (handshake header) = 9
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

// parseHTTPHost tenta extrair o cabeÃ§alho Host de uma requisiÃ§Ã£o HTTP
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
// ARP SPOOFING (Man-in-the-Middle) - InterceptaÃ§Ã£o de TrÃ¡fego
// =====================================================================

// resolveGatewayMAC descobre o MAC do gateway enviando um ARP Request e esperando a resposta
