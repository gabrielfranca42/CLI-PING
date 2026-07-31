package sniffer

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gabrifranca/cli_ping/internal/report"

	"github.com/gabrifranca/cli_ping/internal/scanner"

	manuf "github.com/timest/gomanuf"
)

// analyzeLogs pega a estrutura preenchida durante a captura e emite um relatÃ³rio analÃ­tico
func (s *SnifferService) analyzeLogs(logs *SnifferLogs) {
	// Fase de Enumeração Ativa: Para cada IP descoberto que não foi ignorado, fazer lookup NBNS
	fmt.Println("\n  [*] Iniciando Enumeração Ativa (NBNS) nos hosts descobertos para extrair Usuários e Hostnames...")
	extraService := scanner.NewExtraService()
	
	var wg sync.WaitGroup
	var mu sync.Mutex

	for ip := range logs.DiscoveredHosts {
		// NetBIOS é tipicamente IPv4, ignoramos IPv6 para otimizar
		if ip != "" && !strings.Contains(ip, ":") {
			wg.Add(1)
			go func(targetIP string) {
				defer wg.Done()
				nbnsResult, err := extraService.NBNSLookup(targetIP)
				if err == nil && nbnsResult != nil {
					mu.Lock()
					if nbnsResult.Hostname != "" {
						logs.HostNames[targetIP] = nbnsResult.Hostname
					}
					if nbnsResult.Username != "" {
						logs.HostUsers[targetIP] = nbnsResult.Username
					}
					mu.Unlock()
				}
			}(ip)
		}
	}
	wg.Wait()
	var sb strings.Builder

	sb.WriteString("\n=========================================================================\n")
	sb.WriteString("                   RELATÃ“RIO DE ANÃLISE DE TRÃFEGO PASSIVO               \n")
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

	sb.WriteString("\n  [+] DistribuiÃ§Ã£o de Protocolos:\n")
	if len(logs.ProtocolsCounter) > 0 {
		for proto, count := range logs.ProtocolsCounter {
			sb.WriteString(fmt.Sprintf("      - %-10s: %d pacotes\n", proto, count))
		}
	} else {
		sb.WriteString("      Nenhum protocolo reconhecido.\n")
	}

	sb.WriteString("\n  [+] Rastreador de Acessos DNS (Quem acessou o quÃª):\n")
	if len(logs.DNSQueries) > 0 {
		for domain, ipCounts := range logs.DNSQueries {
			sb.WriteString(fmt.Sprintf("      - DomÃ­nio: %s\n", domain))
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

	sb.WriteString("\n  [+] EstatÃ­sticas de ConexÃµes TCP (Flags):\n")
	for flag, count := range logs.TCPFlagsCounter {
		sb.WriteString(fmt.Sprintf("      - %s: %d ocorrÃªncias\n", flag, count))
	}

	// SeÃ§Ã£o de OS Fingerprinting (TÃ©cnicas 3 e 4 combinadas)
	sb.WriteString("\n  [+] OS Fingerprinting (IdentificaÃ§Ã£o de Dispositivos Desconhecidos):\n")

	knownDevices := loadKnownDevices()
	dbUpdated := false

	// Coleta todos os IPs Ãºnicos que temos alguma informaÃ§Ã£o de OS ou trÃ¡fego
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
	for ip := range logs.DiscoveredHosts {
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

			// TÃ©cnica 2: OS via DHCP
			var osDHCP string
			if os, exists := logs.HostOSByDHCP[ip]; exists {
				osDHCP = os
			}

			// TÃ©cnica 3: OS via DNS Captive Portal / mDNS
			if os, exists := logs.HostOSByDNS[ip]; exists {
				osDNS = os
			}

			// TÃ©cnica 4: OS via TTL Fingerprinting
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

			// EstratÃ©gia 4: HeurÃ­stica de MAC (Aplicada se for Indeterminado ou TTL genÃ©rico)
			if mac != "" && (veredito == "Indeterminado" || veredito == "Linux/Android/iOS/macOS (TTL base 64)") {
				vendor := strings.ToLower(manuf.Search(mac))
				if strings.Contains(vendor, "apple") {
					veredito = "Apple iOS/macOS"
					metodo = "Fabricante MAC + HeurÃ­stica"
				} else if strings.Contains(vendor, "samsung") || strings.Contains(vendor, "motorola") || strings.Contains(vendor, "xiaomi") {
					veredito = "Android"
					metodo = "Fabricante MAC + HeurÃ­stica"
				} else if strings.Contains(vendor, "intel") || strings.Contains(vendor, "dell") || strings.Contains(vendor, "hp") || strings.Contains(vendor, "lenovo") {
					if ttlVal <= 64 {
						veredito = "Windows/Linux PC"
						metodo = "Fabricante MAC + HeurÃ­stica"
					}
				}
			}

			// LÃ³gica de PersistÃªncia (Banco de Dados JSON)
			if mac != "" {
				if knownDev, exists := knownDevices[mac]; exists {
					// Se jÃ¡ conhecÃ­amos esse MAC, e a nova detecÃ§Ã£o Ã© "Indeterminado" ou possivelmente falha (TTL baixo indicando Linux)
					if veredito == "Indeterminado" || (metodo == "TTL Fingerprint" && strings.Contains(veredito, "Linux")) {
						veredito = knownDev.OS
						metodo = "PersistÃªncia Local (BD)"
					}
				}

				// Salva ou atualiza no BD se for um TTL confiÃ¡vel, DNS ou DHCP
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
				metodoExibido = "NÃ£o determinado"
			}

			httpsSB.WriteString("-------------------------------------------------------------------------\n")
			hostnameLabel := ""
			if name, ok := logs.HostNames[ip]; ok && name != "" {
				hostnameLabel = fmt.Sprintf(" (%s)", name)
			}
			userLabel := ""
			if user, ok := logs.HostUsers[ip]; ok && user != "" {
				userLabel = fmt.Sprintf(" | Usuário: %s", user)
			}
			httpsSB.WriteString(fmt.Sprintf("MÃ QUINA: %s%s%s\n", ip, hostnameLabel, userLabel))
			httpsSB.WriteString("-------------------------------------------------------------------------\n")
			httpsSB.WriteString(fmt.Sprintf("  - IP:                  %s\n", ip))

			if mac != "" {
				vendor := manuf.Search(mac)
				if vendor == "" {
					vendor = "Desconhecido"
				}
				httpsSB.WriteString(fmt.Sprintf("  - MAC:                 %s (%s)\n", mac, vendor))
			} else {
				httpsSB.WriteString("  - MAC:                 NÃ£o detectado\n")
			}
			httpsSB.WriteString(fmt.Sprintf("  - Sistema Operacional: %s [MÃ©todo: %s]\n", vereditoExibido, metodoExibido))
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
				httpsSB.WriteString("      Nenhum destino capturado nesta sessÃ£o.\n")
			}
			httpsSB.WriteString("\n")

			// Complementa com MAC se disponÃ­vel
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

			sb.WriteString(fmt.Sprintf("      - IP: %-15s | SO: %-30s | MÃ©todo: %s%s%s\n", ip, veredito, metodo, ttlStr, macStr))
		}

		if dbUpdated {
			saveKnownDevices(knownDevices)
		}
	} else {
		sb.WriteString("      Nenhuma impressÃ£o digital de SO capturada nesta sessÃ£o.\n")
	}

	sb.WriteString("\n  [+] Dispositivos Salvos no BD (SinalizaÃ§Ã£o Offline ou Ausentes nesta captura):\n")
	foundOffline := false
	for mac, dev := range knownDevices {
		// Verifica se o MAC jÃ¡ foi detectado nesta sessÃ£o atual
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

			sb.WriteString(fmt.Sprintf("      - Ãšltimo IP: %-15s | SO: %-30s | MÃ©todo: HistÃ³rico do BD%s%s\n", dev.LastIP, dev.OS, macStr, hostname))
		}
	}
	if !foundOffline {
		sb.WriteString("      Todos os dispositivos conhecidos estÃ£o ativos nesta sessÃ£o ou o banco estÃ¡ vazio.\n")
	}

	sb.WriteString("\n  [!] AnÃ¡lise HeurÃ­stica de SeguranÃ§a:\n")
	hasAlerts := false
	for ip, synCount := range logs.SuspiciousIPs {
		// Threshold: se houver mais de 5 tentativas de SYN a partir de um IP (rudimentar, mas ilustrativo)
		if synCount > 5 {
			sb.WriteString(fmt.Sprintf("      [ALERTA] IP %s gerou %d pacotes SYN. PossÃ­vel varredura de portas (SYN Flood / Scan)!\n", ip, synCount))
			hasAlerts = true
		}
	}
	if !hasAlerts {
		sb.WriteString("      Nenhum trÃ¡fego suspeito evidente (baseado em anomalias de handshake) foi detectado.\n")
	}

	sb.WriteString("=========================================================================\n\n")

	reportContent := sb.String()

	// CriaÃ§Ã£o do log_maquina.txt
	var maquinaSB strings.Builder
	maquinaSB.WriteString("=========================================================================\n")
	maquinaSB.WriteString("                         AJIN - RELATORIO DE MAQUINAS                    \n")
	maquinaSB.WriteString("=========================================================================\n\n")

	hasMachines := false
	for ip, mac := range logs.DiscoveredHosts {
		if ip == "" {
			continue
		}
		
		name := logs.HostNames[ip]
		user := logs.HostUsers[ip]
		
		// SÃ³ inclui no log se tiver alguma informaÃ§Ã£o Ãºtil de mÃ¡quina alÃ©m do IP/MAC
		if name != "" || user != "" {
			hasMachines = true
			maquinaSB.WriteString(fmt.Sprintf("MAQUINA: %s\n", ip))
			if mac != "" {
				vendor := manuf.Search(mac)
				if vendor == "" {
					vendor = "Desconhecido"
				}
				maquinaSB.WriteString(fmt.Sprintf("  - MAC:            %s (%s)\n", mac, vendor))
			}
			if name != "" {
				maquinaSB.WriteString(fmt.Sprintf("  - Hostname:       %s\n", name))
			}
			if user != "" {
				maquinaSB.WriteString(fmt.Sprintf("  - Usuario Logado: %s\n", user))
			}
			maquinaSB.WriteString("-------------------------------------------------------------------------\n")
		}
	}
	
	if !hasMachines { 
		maquinaSB.WriteString("Nenhuma informacao de Hostname ou Usuario foi encontrada nesta sessao.\n")
	}

	// 1. Imprime no console para o usuÃ¡rio ver
	fmt.Print(reportContent)

	// 2, 3 e 4. Salva os relatórios delegando para o pacote report
	reporter := report.NewFileWriter()

	filename := "log_rede.txt"
	_ = reporter.SaveReport(filename, reportContent)

	httpsFilename := "log_https.txt"
	_ = reporter.SaveReport(httpsFilename, httpsSB.String())
	
	maquinaFilename := "log_maquina.txt"
	_ = reporter.SaveReport(maquinaFilename, maquinaSB.String())
}
