package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gabrifranca/cli_ping/internal/domain"
	"github.com/gabrifranca/cli_ping/internal/ping"
	scannerPkg "github.com/gabrifranca/cli_ping/internal/scanner"
	"github.com/gabrifranca/cli_ping/internal/sniffer"
	"github.com/gabrifranca/cli_ping/view"
)

// CLI é o controlador principal do sistema (Controller).
// Ele orquestra as dependências de negócio (Pinger, Scanner) e a visualização (Printer).
type CLI struct {
	service      domain.Pinger
	extraService domain.Scanner
	printer      *view.Printer
}

// NewCLI é o construtor responsável pela injeção de dependências.
// Ele conecta o CLI com as implementações concretas dos serviços de rede.
func NewCLI() *CLI {
	return &CLI{
		service:      ping.NewPingService(),
		extraService: scannerPkg.NewExtraService(),
		printer:      view.NewPrinter(),
	}
}

// RunInteractive inicia o modo de menu interativo (REPL).
// Mantém o usuário em um loop contínuo escolhendo opções até que ele decida sair (opção 10 ou 'exit').
func (c *CLI) RunInteractive() {
	c.printer.PrintBanner()
	scanner := bufio.NewScanner(os.Stdin)

	for {
		c.printMainMenu()
		fmt.Printf("  %s%sajin >%s ", view.Bold, view.Cyan, view.Reset)

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		switch input {
		case "0", "exit", "quit", "q":
			fmt.Printf("\n  %s👋 Até mais!%s\n\n", view.Cyan, view.Reset)
			return
		case "1":
			c.runPingMenu(scanner)
		case "2":
			c.runPortScanMenu(scanner)
		case "3":
			c.runDNSMenu(scanner)
		case "4":
			c.runLoadTestMenu(scanner)
		case "5":
			c.runJWTMenu(scanner)
		case "clear", "cls":
			fmt.Print("\033[H\033[2J")
			c.printer.PrintBanner()
		default:
			c.printer.PrintError("Opção inválida.")
		}
	}
}

// printMainMenu imprime as opções disponíveis na tela inicial do Ajin.
func (c *CLI) printMainMenu() {
	menu := `  %s%sMENU PRINCIPAL:%s
  ──────────────────────────────────────────────────
  %s[ 1 ]%s Ping / Verificação de TLS
  %s[ 2 ]%s Port Scanner (TCP)
  %s[ 3 ]%s Consulta DNS
  %s[ 4 ]%s Load Testing (Stress Test HTTP)
  %s[ 5 ]%s Decodificador JWT
  %s[ 0 ]%s Sair
  ──────────────────────────────────────────────────
`
	fmt.Printf(menu,
		view.Bold, view.Cyan, view.Reset,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Red, view.Reset,
	)
}

// runPingMenu controla o submenu responsável por Testes de Conectividade (Ping e TLS).
func (c *CLI) runPingMenu(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- Ping / TLS Check ---%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  Digite a URL ou o comando (ex: ping google.com, check google.com) ou 'voltar':\n")
	fmt.Printf("  %s%sping >%s ", view.Bold, view.Green, view.Reset)

	if !scanner.Scan() {
		return
	}

	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	tokens := strings.Fields(input)
	command := strings.ToLower(tokens[0])

	switch command {
	case "ping":
		if len(tokens) < 2 {
			c.printer.PrintError("informe pelo menos uma URL. Ex: ping google.com")
			return
		}
		opts, urls, jsonOutput := c.parseFlags(tokens[1:])
		c.executePing(urls, opts, jsonOutput)

	case "check":
		if len(tokens) < 2 {
			c.printer.PrintError("informe uma URL. Ex: check google.com")
			return
		}
		opts := domain.DefaultPingOptions()
		result := c.service.CheckTLS(tokens[1], opts.Timeout)
		c.printer.PrintResult(result)

	default:
		// Treat as a URL directly
		opts := domain.DefaultPingOptions()
		result := c.service.Ping(input, opts)
		c.printer.PrintResult(result)
	}
}

// runPortScanMenu controla o submenu responsável por Análises de Portas TCP e Varreduras de Rede.
func (c *CLI) runPortScanMenu(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- Port Scanner ---%s\n", view.Bold, view.Cyan, view.Reset)
	submenu := `  %s[ 1 ]%s Escanear porta em host remoto
  %s[ 2 ]%s Escanear portas locais (localhost)
  %s[ 3 ]%s Escanear dispositivos na rede WiFi
  %s[ 4 ]%s Modo Promíscuo (Escuta Passiva)
  %s[ 5 ]%s ARP Spoof (Man-in-the-Middle)
  %s[ 0 ]%s Voltar
`
	fmt.Printf(submenu,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Yellow, view.Reset,
		view.Red, view.Reset,
	)
	fmt.Printf("  %s%sport >%s ", view.Bold, view.Green, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())

	switch input {
	case "0", "voltar":
		return
	case "1":
		c.runRemotePortScan(scanner)
	case "2":
		c.runLocalPortScan(scanner)
	case "3":
		c.runNetworkScan(scanner)
	case "4":
		c.runPromiscuousMode(scanner)
	case "5":
		c.runARPSpoof(scanner)
	default:
		c.printer.PrintError("Opção inválida.")
	}
}

// runPromiscuousMode ativa o Sniffer de Rede em Modo Promíscuo para captura e análise passiva de tráfego.
func (c *CLI) runPromiscuousMode(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s[!] AVISO:%s O Modo Promíscuo requer driver Npcap e privilégios de Administrador.\n", view.Yellow, view.Reset)
	fmt.Printf("  %sDeseja iniciar a escuta passiva? (s/n):%s ", view.Bold, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	input = strings.ToLower(input)
	if input != "s" && input != "y" {
		return
	}

	snifferSvc := sniffer.NewSnifferService()
	ctx, cancel := context.WithCancel(context.Background())

	// Roda o sniffer em segundo plano
	go snifferSvc.SniffNetwork(ctx)

	// Aguarda o usuário apertar Enter para cancelar
	scanner.Scan()
	cancel()
	
	// Aguarda um instante para o sniffer terminar de printar
	time.Sleep(200 * time.Millisecond)
}

// runARPSpoof inicia a funcionalidade de Man-in-the-Middle, injetando pacotes ARP na rede local.
// Após o anexo bem-sucedido, apresenta um submenu de monitoramento defensivo de rede.
func (c *CLI) runARPSpoof(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- ARP Spoof (Man-in-the-Middle) ---%s\n", view.Bold, view.Red, view.Reset)
	fmt.Printf("  %s[!] AVISO: Esta funcionalidade intercepta o tráfego de rede de um alvo.%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s[!] Use APENAS em redes que você tem autorização para auditar.%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s[!] Requer Npcap e privilégios de Administrador.%s\n", view.Yellow, view.Reset)
	fmt.Printf("\n  Escolha uma opção:\n")
	fmt.Printf("  %s[ 1 ]%s Anexar apenas um IP\n", view.Yellow, view.Reset)
	fmt.Printf("  %s[ 2 ]%s Anexar vários IPs\n", view.Yellow, view.Reset)
	fmt.Printf("  %s[ 0 ]%s Voltar\n", view.Red, view.Reset)
	fmt.Printf("  %s%smitm > %s ", view.Bold, view.Red, view.Reset)

	if !scanner.Scan() {
		return
	}
	option := strings.TrimSpace(scanner.Text())

	var targetIPs []string
	var manualMACs []string

	if option == "0" || option == "voltar" {
		return
	} else if option == "1" {
		fmt.Printf("\n  Digite o IP do alvo (ex: 10.67.83.16) ou 'voltar':\n")
		fmt.Printf("  %s%smitm > %s ", view.Bold, view.Red, view.Reset)
		if !scanner.Scan() {
			return
		}
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" || ip == "voltar" {
			return
		}
		targetIPs = append(targetIPs, ip)

		fmt.Printf("\n  Digite o MAC do alvo (ex: 70:a8:d3:d1:51:91) ou ENTER para auto-resolver:\n")
		fmt.Printf("  %s%smac > %s ", view.Bold, view.Red, view.Reset)
		if scanner.Scan() {
			mac := strings.TrimSpace(scanner.Text())
			if mac != "" {
				manualMACs = append(manualMACs, mac)
			}
		}
	} else if option == "2" {
		fmt.Printf("\n  Digite os IPs dos alvos separados por espaço (ex: 10.0.0.5 10.0.0.6) ou 'voltar':\n")
		fmt.Printf("  %s%smitm > %s ", view.Bold, view.Red, view.Reset)
		if !scanner.Scan() {
			return
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "" || input == "voltar" {
			return
		}
		targetIPs = strings.Fields(input)

		fmt.Printf("\n  Digite os MACs dos alvos separados por espaço, na mesma ordem (ou ENTER para auto-resolver todos):\n")
		fmt.Printf("  %s%smac > %s ", view.Bold, view.Red, view.Reset)
		if scanner.Scan() {
			macsInput := strings.TrimSpace(scanner.Text())
			if macsInput != "" {
				manualMACs = strings.Fields(macsInput)
			}
		}
	} else {
		c.printer.PrintError("Opção inválida.")
		return
	}

	if len(targetIPs) == 0 {
		return
	}

	// Confirmação de segurança
	fmt.Printf("\n  %s[!] Você tem certeza que deseja interceptar o tráfego de %d alvo(s)? (s/n):%s ", view.Red, len(targetIPs), view.Reset)
	if !scanner.Scan() {
		return
	}
	confirm := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if confirm != "s" && confirm != "y" {
		fmt.Printf("  Operação cancelada.\n")
		return
	}

	snifferSvc := sniffer.NewSnifferService()
	ctx, cancel := context.WithCancel(context.Background())

	// Roda o MitM em segundo plano para cada alvo
	for i, ip := range targetIPs {
		mac := ""
		if i < len(manualMACs) {
			mac = manualMACs[i]
		}
		go snifferSvc.ARPSpoofMitM(ctx, ip, mac)
	}

	// Aguarda um momento para o ARP Spoof se estabilizar
	fmt.Printf("\n  %s[*] Aguardando estabilização do MitM...%s\n", view.Cyan, view.Reset)
	time.Sleep(4 * time.Second)

	// === SUBMENU DE MONITORAMENTO PÓS-ANEXO ===
	c.runMonitorMenu(scanner, snifferSvc, targetIPs, ctx, cancel)
}

// runMonitorMenu apresenta o submenu de monitoramento de rede após o IP ser anexado com sucesso.
// Permite ao operador monitorar tráfego em tempo real, bloquear WiFi defensivamente e gerar logs.
func (c *CLI) runMonitorMenu(scanner *bufio.Scanner, snifferSvc *sniffer.SnifferService, targetIPs []string, parentCtx context.Context, parentCancel context.CancelFunc) {
	// Estado de bloqueio local (para exibição no menu)
	wifiBlocked := false

	for {
		fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
		fmt.Printf("  %s%s       MONITORAMENTO DE REDE — PAINEL DEFENSIVO         %s\n", view.Bold, view.Cyan, view.Reset)
		fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
		fmt.Printf("  %sIPs Anexados: %s%s\n", view.White, strings.Join(targetIPs, ", "), view.Reset)
		if wifiBlocked {
			fmt.Printf("  %s🛑 STATUS: BLOQUEIO TOTAL ATIVO (ARP Black Hole)%s\n", view.Red, view.Reset)
		} else {
			fmt.Printf("  %s✅ STATUS: MitM ativo — Alvo(s) com internet normal%s\n", view.Green, view.Reset)
		}
		fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", view.Cyan, view.Reset)
		fmt.Printf("  %s[ 1 ]%s 📡 Monitorar Tráfego (Logs em tempo real + log_ip.txt)\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 2 ]%s 🛑 Negar WiFi (Bloqueio TOTAL — ARP Black Hole)\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 3 ]%s ✅ Restaurar WiFi (Liberar acesso do alvo)\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 0 ]%s 🔙 Encerrar MitM e Restaurar Rede\n", view.Red, view.Reset)
		fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", view.Cyan, view.Reset)
		fmt.Printf("  %s%smonitor > %s ", view.Bold, view.Green, view.Reset)

		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		switch input {
		case "0", "voltar", "exit":
			// Se estiver bloqueado, restaura antes de sair
			if wifiBlocked {
				fmt.Printf("\n  %s[*] Restaurando acesso WiFi dos alvos antes de encerrar...%s\n", view.Yellow, view.Reset)
				sniffer.EnableIPForwardingPublic()
			}
			// Encerra o MitM e restaura a rede
			fmt.Printf("\n  %s[*] Encerrando MitM e restaurando tabelas ARP...%s\n", view.Yellow, view.Reset)
			parentCancel()
			time.Sleep(3 * time.Second)
			fmt.Printf("  %s[✓] Rede restaurada com sucesso.%s\n\n", view.Green, view.Reset)
			return

		case "1":
			c.runTrafficMonitor(scanner, snifferSvc, targetIPs[0])

		case "2":
			// Negar WiFi — Bloqueio TOTAL via ARP Black Hole
			fmt.Printf("\n  %s[!] ATENÇÃO: Isso cortará TOTALMENTE o acesso à internet do(s) alvo(s).%s\n", view.Red, view.Reset)
			fmt.Printf("  %s[!] Técnica: ARP Black Hole — O gateway apontará para um MAC inexistente.%s\n", view.Yellow, view.Reset)
			fmt.Printf("  %sDeseja prosseguir com o bloqueio total? (s/n):%s ", view.Bold, view.Reset)
			if !scanner.Scan() {
				continue
			}
			confirmBlock := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if confirmBlock == "s" || confirmBlock == "y" {
				// Desabilita IP Forwarding como camada extra
				sniffer.DisableIPForwardingPublic()
				// Ativa o bloqueio via Black Hole para cada alvo
				snifferSvc.ActivateBlackHole(targetIPs)
				wifiBlocked = true

				fmt.Printf("\n  %s[🛑 BLOQUEIO TOTAL ATIVO]%s\n", view.Red, view.Reset)
				fmt.Printf("  %s    → Técnica: ARP Black Hole (MAC de:ad:be:ef:00:01)%s\n", view.Yellow, view.Reset)
				fmt.Printf("  %s    → O(s) alvo(s) não consegue(m) acessar NENHUM recurso de rede.%s\n", view.Yellow, view.Reset)
				fmt.Printf("  %s    → Tráfego é descartado pelo switch — bloqueio 100%% efetivo.%s\n", view.Yellow, view.Reset)
				fmt.Printf("  %s    → Use a opção [3] para restaurar o acesso.%s\n\n", view.Cyan, view.Reset)
			}

		case "3":
			// Restaurar WiFi — desativa Black Hole e reativa MitM normal
			snifferSvc.DeactivateBlackHole(targetIPs)
			sniffer.EnableIPForwardingPublic()
			wifiBlocked = false

			fmt.Printf("\n  %s[✓ RESTAURADO]%s WiFi dos alvos foi liberado.\n", view.Green, view.Reset)
			fmt.Printf("  %s    → MitM ainda ativo — tráfego interceptado e encaminhado normalmente.%s\n", view.White, view.Reset)
			fmt.Printf("  %s    → O(s) alvo(s) pode(m) acessar a internet normalmente.%s\n\n", view.White, view.Reset)

		default:
			c.printer.PrintError("Opção inválida.")
		}
	}
}

// runTrafficMonitor inicia o monitoramento de tráfego em tempo real para um IP alvo.
// O usuário pode navegar normalmente enquanto os logs são exibidos na tela.
// Ao encerrar (ENTER), gera automaticamente o arquivo log_ip.txt.
func (c *CLI) runTrafficMonitor(scanner *bufio.Scanner, snifferSvc *sniffer.SnifferService, targetIP string) {
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s%s    📡 MONITORAMENTO EM TEMPO REAL — %s                   %s\n", view.Bold, view.Cyan, targetIP, view.Reset)
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s[*] Capturando todo o tráfego de %s em tempo real...%s\n", view.White, targetIP, view.Reset)
	fmt.Printf("  %s[*] O alvo pode navegar normalmente. Logs aparecem abaixo.%s\n", view.White, view.Reset)
	fmt.Printf("  %s[*] 🔍 = DNS | 🔒 = HTTPS | 🌐 = HTTP | 🚨 = Ameaça Detectada%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s[!] Pressione ENTER para encerrar e gerar log_ip.txt%s\n\n", view.Yellow, view.Reset)

	monCtx, monCancel := context.WithCancel(context.Background())
	blockCh := make(chan bool, 1)
	alertCh := make(chan string, 100)

	// Goroutine para processar alertas (exibição assíncrona)
	go func() {
		for {
			select {
			case <-monCtx.Done():
				return
			case alert := <-alertCh:
				_ = alert // Alertas já são impressos no monitor.go
			}
		}
	}()

	// Inicia o monitoramento em background
	go snifferSvc.MonitorTarget(monCtx, targetIP, "", nil, nil, nil, nil, blockCh, alertCh)

	// Aguarda ENTER para encerrar
	scanner.Scan()
	monCancel()

	// Aguarda finalização e geração do log
	time.Sleep(500 * time.Millisecond)

	fmt.Printf("\n  %s[✓] Monitoramento encerrado. Arquivo log_ip.txt gerado.%s\n", view.Green, view.Reset)
}

// runRemotePortScan pede um IP ao usuário e realiza um port scan básico contra um host remoto.
func (c *CLI) runRemotePortScan(scanner *bufio.Scanner) {
	fmt.Printf("\n  Digite o host e a porta (ex: google.com 443) ou 'voltar':\n")
	fmt.Printf("  %s%sscan >%s ", view.Bold, view.Green, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	var host string
	var port int
	n, _ := fmt.Sscanf(input, "%s %d", &host, &port)
	if n != 2 {
		c.printer.PrintError("formato inválido. Use: <host> <porta>")
		return
	}

	c.printer.PrintInfo(fmt.Sprintf("Escaneando porta %d em %s ...", port, host))
	open := c.extraService.PortScan(host, port)
	if open {
		fmt.Printf("  %s✓ Porta %d aberta!%s\n\n", view.Green, port, view.Reset)
	} else {
		fmt.Printf("  %s✗ Porta %d fechada/timeout.%s\n\n", view.Red, port, view.Reset)
	}
}

// runLocalPortScan analisa a própria máquina (localhost) em busca de portas TCP abertas num intervalo definido.
func (c *CLI) runLocalPortScan(scanner *bufio.Scanner) {
	fmt.Printf("\n  Range de portas (ex: 1 1024) ou 'all' para 1-65535:\n")
	fmt.Printf("  %s%srange >%s ", view.Bold, view.Green, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	var start, end int
	if input == "all" {
		start, end = 1, 65535
	} else {
		n, _ := fmt.Sscanf(input, "%d %d", &start, &end)
		if n != 2 || start < 1 || end > 65535 || start > end {
			c.printer.PrintError("Range inválido. Use: <inicio> <fim> (ex: 1 1024)")
			return
		}
	}

	total := end - start + 1
	c.printer.PrintInfo(fmt.Sprintf("Escaneando %d portas em localhost ...", total))

	startTime := time.Now()
	openPorts := c.extraService.LocalPortScan(start, end, 200)
	elapsed := time.Since(startTime)

	fmt.Println()
	if len(openPorts) == 0 {
		fmt.Printf("  %sNenhuma porta aberta encontrada.%s\n\n", view.Yellow, view.Reset)
		return
	}

	for _, port := range openPorts {
		name := scannerPkg.PortNames[port]
		if name != "" {
			fmt.Printf("  %s✓ Porta %-5d (%s)%s\n", view.Green, port, name, view.Reset)
		} else {
			fmt.Printf("  %s✓ Porta %d%s\n", view.Green, port, view.Reset)
		}
	}

	fmt.Printf("\n  %s%d porta(s) aberta(s) em %v%s\n\n",
		view.White, len(openPorts), elapsed.Round(time.Millisecond), view.Reset)
}

// runNetworkScan varre ativamente toda a sub-rede enviando requisições (Ping Sweep e Port Scan)
// para montar um mapa dos dispositivos conectados atualmente.
func (c *CLI) runNetworkScan(scanner *bufio.Scanner) {
	localIP, err := c.extraService.GetLocalIP()
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro ao detectar IP local: %v", err))
		return
	}

	base := c.extraService.GetNetworkBase(localIP)
	if base == "" {
		c.printer.PrintError("Não foi possível determinar a rede.")
		return
	}

	fmt.Printf("\n  %sSeu IP: %s%s\n", view.White, localIP, view.Reset)
	fmt.Printf("  %sRede detectada: %s.0/24%s\n", view.White, base, view.Reset)
	c.printer.PrintInfo(fmt.Sprintf("Escaneando 254 hosts com %d portas comuns ...\n", len(scannerPkg.CommonPorts)))

	startTime := time.Now()

	onFound := func(host domain.NetworkHost) {
		portStrs := []string{}
		for _, p := range host.OpenPorts {
			name := scannerPkg.PortNames[p]
			if name != "" {
				portStrs = append(portStrs, fmt.Sprintf("%d (%s)", p, name))
			} else {
				portStrs = append(portStrs, fmt.Sprintf("%d", p))
			}
		}

		label := ""
		if host.IP == localIP {
			label = view.Cyan + " ← você" + view.Reset
		} else if host.IP == base+".1" {
			label = view.Cyan + " ← gateway" + view.Reset
		}

		fmt.Printf("  %s✓ %-15s%s │ Portas: %s%s\n",
			view.Green, host.IP, view.Reset,
			strings.Join(portStrs, ", "), label)
	}

	results := c.extraService.NetworkScan(base, scannerPkg.CommonPorts, onFound)
	elapsed := time.Since(startTime)

	if len(results) == 0 {
		fmt.Printf("\n  %sNenhum dispositivo encontrado.%s\n\n", view.Yellow, view.Reset)
		return
	}

	fmt.Printf("\n  %s%d dispositivo(s) encontrado(s) em %v%s\n\n",
		view.White, len(results), elapsed.Round(time.Millisecond), view.Reset)
}

// runDNSMenu resolve nomes de domínio para descobrir quais IPs estão associados a uma URL.
func (c *CLI) runDNSMenu(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- Consulta DNS ---%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  Digite o host (ex: google.com) ou 'voltar':\n")
	fmt.Printf("  %s%sdns >%s ", view.Bold, view.Green, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	c.printer.PrintInfo(fmt.Sprintf("Consultando IPs para %s ...", input))
	ips, err := c.extraService.DNSLookup(input)
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro ao consultar DNS: %v", err))
		return
	}
	for _, ip := range ips {
		fmt.Printf("  %s- %s%s\n", view.White, ip, view.Reset)
	}
	fmt.Println()
}

// runLoadTestMenu cria dezenas de conexões concorrentes para testar a resiliência de um servidor HTTP.
func (c *CLI) runLoadTestMenu(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- Load Testing ---%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  Digite a URL, quantidade de requisições e concorrência (ex: http://google.com 100 10) ou 'voltar':\n")
	fmt.Printf("  %s%sload >%s ", view.Bold, view.Green, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	var url string
	var reqs, conc int
	n, _ := fmt.Sscanf(input, "%s %d %d", &url, &reqs, &conc)
	if n != 3 {
		c.printer.PrintError("formato inválido. Use: <url> <qtd> <concorrencia>")
		return
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	c.printer.PrintInfo(fmt.Sprintf("Enviando %d requisições (%d simultâneas) para %s ...", reqs, conc, url))
	success, failed, duration := c.extraService.LoadTest(url, reqs, conc)

	fmt.Printf("  %sTempo Total: %v%s\n", view.White, duration, view.Reset)
	fmt.Printf("  %sSucesso: %d%s\n", view.Green, success, view.Reset)
	fmt.Printf("  %sFalha:   %d%s\n\n", view.Red, failed, view.Reset)
}

// runJWTMenu decodifica a base64 de um token JWT para facilitar a leitura de suas Claims (cabeçalho e payload).
func (c *CLI) runJWTMenu(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- Decodificador JWT ---%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  Cole o seu token JWT ou digite 'voltar':\n")
	fmt.Printf("  %s%sjwt >%s ", view.Bold, view.Green, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	header, payload, err := c.extraService.DecodeJWT(input)
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro ao decodificar: %v", err))
		return
	}

	fmt.Printf("\n  %s[Header]%s\n  %s\n", view.Cyan, view.Reset, header)
	fmt.Printf("\n  %s[Payload]%s\n  %s\n\n", view.Cyan, view.Reset, payload)
}

// executePing runs the ping logic for interactive mode.
func (c *CLI) executePing(args []string, opts domain.PingOptions, jsonOutput bool) {
	if len(args) == 0 {
		c.printer.PrintError("nenhuma URL fornecida.")
		return
	}

	if len(args) == 1 && opts.Count > 1 {
		// Repeated ping mode
		c.printer.PrintInfo(fmt.Sprintf("Pinging %s × %d ...", args[0], opts.Count))
		fmt.Println()
		results := c.service.PingRepeat(args[0], opts)

		if jsonOutput {
			c.printer.PrintJSON(results)
			return
		}

		for _, r := range results {
			c.printer.PrintResult(r)
		}
		c.printer.PrintRepeatSummary(results)
	} else {
		// Single or multi-URL mode
		c.printer.PrintInfo(fmt.Sprintf("Pinging %d endpoint(s) ...", len(args)))
		fmt.Println()

		results := c.service.PingMultiple(args, opts)

		if jsonOutput {
			c.printer.PrintJSON(results)
			return
		}

		if len(results) == 1 {
			c.printer.PrintResult(results[0])
		} else {
			c.printer.PrintResultsTable(results)
		}
	}
}

// RunPing handles the main "ping" command logic (non-interactive).
func (c *CLI) RunPing(args []string, opts domain.PingOptions, jsonOutput bool) {
	if len(args) == 0 {
		c.printer.PrintError("no URL(s) provided. Usage: cli-ping ping <url> [url2] ...")
		os.Exit(1)
	}

	c.printer.PrintBanner()
	c.executePing(args, opts, jsonOutput)
}

// RunCheck handles the "check" subcommand for TLS verification (non-interactive).
func (c *CLI) RunCheck(args []string, opts domain.PingOptions) {
	if len(args) == 0 {
		c.printer.PrintError("no URL provided. Usage: cli-ping check <url>")
		os.Exit(1)
	}

	c.printer.PrintBanner()
	c.printer.PrintInfo(fmt.Sprintf("Checking TLS for %s ...", args[0]))
	fmt.Println()

	result := c.service.CheckTLS(args[0], opts.Timeout)
	c.printer.PrintResult(result)
}

// RunHelp displays usage information.
func (c *CLI) RunHelp() {
	c.printer.PrintBanner()

	help := `
  %sUSAGE:%s
    ajin                                  Abrir modo interativo
    ajin <command> [flags] <url>          Executar direto

  %sCOMMANDS:%s
    ping       Ping one or more endpoints and report status
    check      Check TLS certificate validity for an endpoint
    help       Show this help message

  %sFLAGS:%s
    -t, --timeout <seconds>     Request timeout in seconds (default: 10)
    -c, --count <n>             Number of pings to send (default: 1)
    -i, --interval <seconds>    Interval between pings in seconds (default: 1)
    -m, --method <METHOD>       HTTP method to use (default: GET)
    --no-follow                 Do not follow HTTP redirects
    --json                      Output results as JSON

  %sEXAMPLES:%s
    ajin                                      (modo interativo)
    ajin ping google.com
    ajin ping https://my-app.onrender.com
    ajin ping -c 5 -i 2 api.example.com
    ajin check my-app.onrender.com
`
	fmt.Printf(help,
		view.Bold+view.Cyan, view.Reset,
		view.Bold+view.Cyan, view.Reset,
		view.Bold+view.Cyan, view.Reset,
		view.Bold+view.Cyan, view.Reset,
	)
}

// ParseAndRun é o ponto de entrada principal ao executar a ferramenta a partir da linha de comando com argumentos (flags), sem abrir o menu.
func (c *CLI) ParseAndRun() {
	args := os.Args[1:]

	// No arguments = interactive mode
	if len(args) == 0 {
		c.RunInteractive()
		return
	}

	command := strings.ToLower(args[0])
	remaining := args[1:]

	switch command {
	case "help", "--help", "-h":
		c.RunHelp()
	case "ping":
		opts, urls, jsonOutput := c.parseFlags(remaining)
		c.RunPing(urls, opts, jsonOutput)
	case "check":
		opts, urls, _ := c.parseFlags(remaining)
		c.RunCheck(urls, opts)
	default:
		// Treat unknown commands as URLs to ping
		opts, urls, jsonOutput := c.parseFlags(args)
		if len(urls) == 0 {
			urls = args
		}
		c.RunPing(urls, opts, jsonOutput)
	}
}

// parseFlags lê os argumentos de linha de comando (`-t`, `-c`, `-i`) e os converte num objeto PingOptions utilizável.
func (c *CLI) parseFlags(args []string) (domain.PingOptions, []string, bool) {
	opts := domain.DefaultPingOptions()
	urls := []string{}
	jsonOutput := false

	i := 0
	for i < len(args) {
		switch args[i] {
		case "-t", "--timeout":
			if i+1 < len(args) {
				i++
				var sec int
				fmt.Sscanf(args[i], "%d", &sec)
				if sec > 0 {
					opts.Timeout = time.Duration(sec) * time.Second
				}
			}
		case "-c", "--count":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &opts.Count)
			}
		case "-i", "--interval":
			if i+1 < len(args) {
				i++
				var sec int
				fmt.Sscanf(args[i], "%d", &sec)
				if sec > 0 {
					opts.Interval = time.Duration(sec) * time.Second
				}
			}
		case "-m", "--method":
			if i+1 < len(args) {
				i++
				opts.Method = strings.ToUpper(args[i])
			}
		case "--no-follow":
			opts.FollowRedirects = false
		case "--json":
			jsonOutput = true
		case "--headers":
			opts.ShowHeaders = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				urls = append(urls, args[i])
			}
		}
		i++
	}

	return opts, urls, jsonOutput
}
