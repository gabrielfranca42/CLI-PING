package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gabrifranca/cli_ping/internal/domain"
	"github.com/gabrifranca/cli_ping/internal/ping"
	scannerPkg "github.com/gabrifranca/cli_ping/internal/scanner"
	"github.com/gabrifranca/cli_ping/internal/sniffer"
	"github.com/gabrifranca/cli_ping/internal/wifi"
	"github.com/gabrifranca/cli_ping/view"
)

// CLI é o controlador principal do sistema (Controller).
// Ele orquestra as dependências de negócio (Pinger, Scanner) e a visualização (Printer).
type CLI struct {
	service      domain.Pinger
	extraService domain.Scanner
	printer      *view.Printer
	wifiService  *wifi.WiFiService
}

// NewCLI é o construtor responsável pela injeção de dependências.
// Ele conecta o CLI com as implementações concretas dos serviços de rede.
func NewCLI() *CLI {
	return &CLI{
		service:      ping.NewPingService(),
		extraService: scannerPkg.NewExtraService(),
		printer:      view.NewPrinter(),
		wifiService:  wifi.NewWiFiService(),
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
		case "6":
			c.runWiFiMenu(scanner)
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
  %s[ 6 ]%s WiFi Auditor (Scanner + Hashcat GPU)
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
		view.Magenta, view.Reset,
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
	fmt.Printf("  %s[ 3 ]%s TODOS os dispositivos da rede\n", view.Yellow, view.Reset)
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
	} else if option == "3" {
		c.runARPSpoofAll(scanner)
		return
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

	// Flag compartilhada para controlar exibição de logs em tempo real
	var showLogs atomic.Bool
	var showTracer atomic.Bool
	
	// Flag compartilhada para controlar bloqueio (Negar WiFi via Software Drop)
	var isBlocked atomic.Bool

	// Roda o MitM em segundo plano para cada alvo
	for i, ip := range targetIPs {
		mac := ""
		if i < len(manualMACs) {
			mac = manualMACs[i]
		}
		go snifferSvc.ARPSpoofMitM(ctx, ip, mac, &showLogs, &showTracer, &isBlocked)
	}

	// Aguarda um momento para o ARP Spoof se estabilizar
	fmt.Printf("\n  %s[*] Aguardando estabilização do MitM...%s\n", view.Cyan, view.Reset)
	time.Sleep(4 * time.Second)

	// === SUBMENU DE MONITORAMENTO PÓS-ANEXO ===
	c.runMonitorMenu(scanner, snifferSvc, targetIPs, ctx, cancel, &showLogs, &showTracer, &isBlocked)
}

// runMonitorMenu apresenta o submenu de monitoramento de rede após o IP ser anexado com sucesso.
// Permite ao operador monitorar tráfego em tempo real, bloquear WiFi defensivamente e gerar logs.
// O bloqueio usa Software Drop: o MitM continua atraindo pacotes, mas o nosso Sniffer descarta tudo na memória.
func (c *CLI) runMonitorMenu(scanner *bufio.Scanner, snifferSvc *sniffer.SnifferService, targetIPs []string, parentCtx context.Context, parentCancel context.CancelFunc, showLogs *atomic.Bool, showTracer *atomic.Bool, isBlocked *atomic.Bool) {

	for {
		fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
		fmt.Printf("  %s%s       MONITORAMENTO DE REDE — PAINEL DEFENSIVO         %s\n", view.Bold, view.Cyan, view.Reset)
		fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
		fmt.Printf("  %sIPs Anexados: %s%s\n", view.White, strings.Join(targetIPs, ", "), view.Reset)
		if isBlocked.Load() {
			fmt.Printf("  %s🛑 STATUS: BLOQUEIO TOTAL ATIVO (Software Drop)%s\n", view.Red, view.Reset)
		} else {
			fmt.Printf("  %s✅ STATUS: MitM ativo — Alvo(s) com internet normal%s\n", view.Green, view.Reset)
		}
		fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", view.Cyan, view.Reset)
		fmt.Printf("  %s[ 1 ]%s 📡 Monitorar Tráfego (Tela focada em logs)\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 2 ]%s 🛑 Negar WiFi (Bloqueio TOTAL — Software Drop)\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 3 ]%s ✅ Restaurar WiFi (Liberar acesso do alvo)\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 4 ]%s 👁️  Ativar/Desativar Tracer (Ping) em segundo plano\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 0 ]%s 🔙 Encerrar MitM e Restaurar Rede (gera log_ip.txt)\n", view.Red, view.Reset)
		fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", view.Cyan, view.Reset)
		fmt.Printf("  %s%smonitor > %s ", view.Bold, view.Green, view.Reset)

		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())

		switch input {
		case "0", "voltar", "exit":
			// Se estiver bloqueado, restaura acesso antes de sair
			if isBlocked.Load() {
				fmt.Printf("\n  %s[*] Restaurando acesso WiFi dos alvos antes de encerrar...%s\n", view.Yellow, view.Reset)
				isBlocked.Store(false)
			}
			// Desliga os logs antes de encerrar
			showLogs.Store(false)
			showTracer.Store(false)
			// Encerra o MitM e restaura a rede (ARPSpoofMitM gera log_ip.txt ao encerrar)
			fmt.Printf("\n  %s[*] Encerrando MitM e restaurando tabelas ARP...%s\n", view.Yellow, view.Reset)
			parentCancel()
			time.Sleep(3 * time.Second)
			fmt.Printf("  %s[✓] Rede restaurada com sucesso. Arquivo log_ip.txt gerado.%s\n\n", view.Green, view.Reset)
			return

		case "1":
			c.runTrafficMonitor(scanner, showLogs, targetIPs[0])

		case "2":
			// Negar WiFi — Software Drop: joga os pacotes no lixo na memória do Go
			fmt.Printf("\n  %s[!] ATENÇÃO: Isso cortará TOTALMENTE o acesso à internet do(s) alvo(s).%s\n", view.Red, view.Reset)
			fmt.Printf("  %s[!] Técnica: Software Drop — O sniffer dropará os pacotes interceptados.%s\n", view.Yellow, view.Reset)
			fmt.Printf("  %sDeseja prosseguir com o bloqueio total? (s/n):%s ", view.Bold, view.Reset)
			if !scanner.Scan() {
				continue
			}
			confirmBlock := strings.TrimSpace(strings.ToLower(scanner.Text()))
			if confirmBlock == "s" || confirmBlock == "y" {
				isBlocked.Store(true)

				fmt.Printf("\n  %s[🛑 BLOQUEIO TOTAL ATIVO]%s\n", view.Red, view.Reset)
				fmt.Printf("  %s    → Técnica: Software Drop%s\n", view.Yellow, view.Reset)
				fmt.Printf("  %s    → O MitM continua atraindo o tráfego do alvo.%s\n", view.Yellow, view.Reset)
				fmt.Printf("  %s    → O Sniffer (Ajin) está descartando pacotes na memória — bloqueio 100%% efetivo.%s\n", view.Yellow, view.Reset)
				fmt.Printf("  %s    → Use a opção [3] para restaurar o acesso.%s\n\n", view.Cyan, view.Reset)
			}

		case "3":
			// Restaurar WiFi — libera pacote no sniffer
			isBlocked.Store(false)

			fmt.Printf("\n  %s[✓ RESTAURADO]%s WiFi dos alvos foi liberado.\n", view.Green, view.Reset)
			fmt.Printf("  %s    → Software Drop desativado — tráfego sendo encaminhado normalmente.%s\n", view.White, view.Reset)
			fmt.Printf("  %s    → MitM ainda ativo — interceptação continua.%s\n", view.White, view.Reset)
			fmt.Printf("  %s    → O(s) alvo(s) pode(m) acessar a internet normalmente.%s\n\n", view.White, view.Reset)

		case "4":
			// Alternar a exibição do Tracer (Ping) em background
			currentState := showTracer.Load()
			showTracer.Store(!currentState)
			if !currentState {
				fmt.Printf("\n  %s[✓] Tracer (ICMP Ping) ATIVADO no fundo.%s\n", view.Green, view.Reset)
				fmt.Printf("  %s    → O terminal continuará aceitando comandos (ex: 2 para bloquear).%s\n\n", view.White, view.Reset)
			} else {
				fmt.Printf("\n  %s[✓] Tracer (ICMP Ping) DESATIVADO.%s\n\n", view.Yellow, view.Reset)
			}

		case "":
			if showLogs.Load() {
				showLogs.Store(false)
				showTracer.Store(false)
				fmt.Printf("\n  %s[✓] Logs em tempo real DESATIVADOS.%s\n\n", view.Yellow, view.Reset)
			}

		default:
			c.printer.PrintError("Opção inválida.")
		}
	}
}

// runTrafficMonitor ativa a exibição de logs em tempo real do ARPSpoofMitM já em execução.
// Não abre um novo pcap — apenas liga/desliga a flag showLogs da goroutine existente.
// O log_ip.txt é gerado quando o MitM é encerrado (opção 0), não aqui.
func (c *CLI) runTrafficMonitor(scanner *bufio.Scanner, showLogs *atomic.Bool, targetIP string) {
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s%s    📡 MONITORAMENTO EM TEMPO REAL — %s                   %s\n", view.Bold, view.Cyan, targetIP, view.Reset)
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s[*] Exibindo tráfego interceptado de %s em tempo real...%s\n", view.White, targetIP, view.Reset)
	fmt.Printf("  %s[*] 🔍 = DNS | 🔒 = HTTPS | 🌐 = HTTP%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s[!] Pressione ENTER para parar a exibição e voltar ao menu.%s\n\n", view.Yellow, view.Reset)

	// Liga a exibição de logs em tempo real
	showLogs.Store(true)

	// Aguarda ENTER para parar a exibição
	scanner.Scan()

	// Desliga a exibição de logs (a captura continua em background)
	showLogs.Store(false)

	fmt.Printf("\n  %s[✓] Exibição encerrada. A captura continua em background.%s\n", view.Green, view.Reset)
	fmt.Printf("  %s[*] O log_ip.txt será gerado ao encerrar o MitM (opção 0).%s\n", view.White, view.Reset)
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

// ═══════════════════════════════════════════════════════════════════════════
// ALL MODE — Auto-detecção de alvos via log_rede.txt
// ═══════════════════════════════════════════════════════════════════════════

// discoveredTarget representa um dispositivo encontrado no log_rede.txt
type discoveredTarget struct {
	IP     string
	MAC    string
	Vendor string
}

// firewallVendors contém palavras-chave para identificar equipamentos de infraestrutura de rede
var firewallVendors = []string{
	"aruba", "cisco", "juniper", "fortinet", "palo alto",
	"ubiquiti", "mikrotik", "sonicwall", "checkpoint", "ruckus",
	"hewlett packard enterprise",
}

// isFirewallVendor verifica se o fabricante corresponde a um equipamento de rede/firewall
func isFirewallVendor(vendor string) bool {
	v := strings.ToLower(vendor)
	for _, fw := range firewallVendors {
		if strings.Contains(v, fw) {
			return true
		}
	}
	return false
}

// parseLogRede lê o log_rede.txt e extrai todos os dispositivos IPv4 com seus MACs e fabricantes.
func parseLogRede() ([]discoveredTarget, error) {
	data, err := os.ReadFile("log_rede.txt")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var targets []discoveredTarget
	seen := make(map[string]bool) // Dedup por IP

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "- IP:") || !strings.Contains(line, "| MAC:") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		// Extrai IP
		ipPart := strings.TrimSpace(parts[0])
		ipPart = strings.TrimPrefix(ipPart, "- IP:")
		ip := strings.TrimSpace(ipPart)

		// Ignora IPv6 (apenas IPv4 tem "." e não tem ":")
		if !strings.Contains(ip, ".") {
			continue
		}

		// Ignora duplicatas
		if seen[ip] {
			continue
		}

		// Extrai MAC
		macPart := strings.TrimSpace(parts[1])
		macPart = strings.TrimPrefix(macPart, "MAC:")
		mac := strings.TrimSpace(macPart)

		// Extrai Fabricante
		vendorPart := strings.TrimSpace(parts[2])
		vendorPart = strings.TrimPrefix(vendorPart, "Fabricante:")
		vendor := strings.TrimSpace(vendorPart)

		seen[ip] = true
		targets = append(targets, discoveredTarget{IP: ip, MAC: mac, Vendor: vendor})
	}

	return targets, nil
}

// runARPSpoofAll lê automaticamente o log_rede.txt, filtra firewalls e gateway,
// conecta a todos os dispositivos restantes via MitM e navega ao painel defensivo.
func (c *CLI) runARPSpoofAll(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- ALL: Auto-Detecção de Alvos ---%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s[*] Lendo log_rede.txt para descobrir dispositivos...%s\n", view.White, view.Reset)

	// 1. Parse do log_rede.txt
	allDevices, err := parseLogRede()
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro ao ler log_rede.txt: %v", err))
		fmt.Printf("  %s[!] Execute o Modo Promíscuo (opção 4) primeiro para gerar o relatório.%s\n", view.Yellow, view.Reset)
		return
	}

	if len(allDevices) == 0 {
		c.printer.PrintError("Nenhum dispositivo IPv4 encontrado em log_rede.txt.")
		fmt.Printf("  %s[!] Execute o Modo Promíscuo (opção 4) primeiro para escanear a rede.%s\n", view.Yellow, view.Reset)
		return
	}

	// 2. Descobre nosso IP e gateway
	localIP, err := c.extraService.GetLocalIP()
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro ao detectar IP local: %v", err))
		return
	}
	gatewayBase := c.extraService.GetNetworkBase(localIP)
	gatewayIP := gatewayBase + ".1"

	// 3. Filtra: remove nosso IP, gateway e fabricantes de firewall/rede
	var targets []discoveredTarget
	var skipped []discoveredTarget

	for _, dev := range allDevices {
		if dev.IP == localIP {
			skipped = append(skipped, dev)
			continue
		}
		if dev.IP == gatewayIP {
			skipped = append(skipped, dev)
			continue
		}
		if isFirewallVendor(dev.Vendor) {
			skipped = append(skipped, dev)
			continue
		}
		targets = append(targets, dev)
	}

	// 4. Exibe os resultados
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s%s       ALL — DISPOSITIVOS DETECTADOS AUTOMATICAMENTE       %s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %sSeu IP: %s | Gateway: %s%s\n", view.White, localIP, gatewayIP, view.Reset)
	fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", view.Cyan, view.Reset)

	fmt.Printf("\n  %s[✓] %d alvo(s) válido(s) para MitM:%s\n", view.Green, len(targets), view.Reset)
	for i, t := range targets {
		fmt.Printf("  %s  %2d. %-15s | MAC: %s | %s%s\n", view.White, i+1, t.IP, t.MAC, t.Vendor, view.Reset)
	}

	if len(skipped) > 0 {
		fmt.Printf("\n  %s[—] %d dispositivo(s) filtrado(s) (gateway/firewall/próprio):%s\n", view.Yellow, len(skipped), view.Reset)
		for _, s := range skipped {
			reason := "firewall"
			if s.IP == localIP {
				reason = "próprio"
			} else if s.IP == gatewayIP {
				reason = "gateway"
			}
			fmt.Printf("  %s      ✗ %-15s | %s (%s)%s\n", view.Yellow, s.IP, s.Vendor, reason, view.Reset)
		}
	}

	if len(targets) == 0 {
		c.printer.PrintError("Nenhum alvo válido encontrado após filtragem.")
		return
	}

	// 5. Confirmação de segurança
	fmt.Printf("\n  %s[!] Você tem certeza que deseja interceptar o tráfego de TODOS os %d alvo(s)? (s/n):%s ", view.Red, len(targets), view.Reset)
	if !scanner.Scan() {
		return
	}
	confirm := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if confirm != "s" && confirm != "y" {
		fmt.Printf("  Operação cancelada.\n")
		return
	}

	// 6. Lança o MitM para todos os alvos
	snifferSvc := sniffer.NewSnifferService()
	ctx, cancel := context.WithCancel(context.Background())

	var showLogs atomic.Bool
	var showTracer atomic.Bool
	var isBlocked atomic.Bool

	var targetIPs []string
	for _, t := range targets {
		targetIPs = append(targetIPs, t.IP)
		go snifferSvc.ARPSpoofMitM(ctx, t.IP, t.MAC, &showLogs, &showTracer, &isBlocked)
	}

	// 7. Aguarda estabilização
	fmt.Printf("\n  %s[*] Aguardando estabilização do MitM para %d alvos...%s\n", view.Cyan, len(targets), view.Reset)
	time.Sleep(4 * time.Second)

	// 8. Navega para o painel defensivo
	c.runMonitorMenu(scanner, snifferSvc, targetIPs, ctx, cancel, &showLogs, &showTracer, &isBlocked)
}

// ═══════════════════════════════════════════════════════════════════════════
// WIFI AUDITOR — Scanner & Hashcat GPU Wrapper
// ═══════════════════════════════════════════════════════════════════════════

func (c *CLI) runWiFiMenu(scanner *bufio.Scanner) {
	for {
		fmt.Printf("\n  %s%s--- WiFi Auditor (Scanner + Hashcat) ---%s\n", view.Bold, view.Magenta, view.Reset)
		fmt.Printf("  %s[!] ATENÇÃO: Use apenas em redes próprias ou com autorização.%s\n", view.Yellow, view.Reset)
		
		path, err := c.wifiService.FindHashcat()
		if err != nil {
			fmt.Printf("  %s[!] Hashcat: Não encontrado.%s\n", view.Red, view.Reset)
		} else {
			fmt.Printf("  %s[*] Hashcat: %s%s\n", view.Green, path, view.Reset)
		}

		submenu := `  %s[ 1 ]%s Escanear Redes WiFi Próximas
  %s[ 2 ]%s Brute Force (Mask Attack)
  %s[ 3 ]%s Dicionário (Wordlist Attack)
  %s[ 4 ]%s Configurar caminho do Hashcat
  %s[ 5 ]%s Capturar Handshake (Guia + Conversão .hc22000)
  %s[ 0 ]%s Voltar
`
		fmt.Printf(submenu,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Cyan, view.Reset,
			view.Red, view.Reset,
		)
		fmt.Printf("  %s%swifi >%s ", view.Bold, view.Magenta, view.Reset)

		if !scanner.Scan() {
			return
		}
		input := strings.TrimSpace(scanner.Text())

		switch input {
		case "0", "voltar":
			return
		case "1":
			c.runWiFiScanner(scanner)
		case "2":
			c.runWiFiBruteForce(scanner)
		case "3":
			c.runWiFiDictionary(scanner)
		case "4":
			c.runConfigHashcat(scanner)
		case "5":
			c.runHandshakeCapture(scanner)
		default:
			c.printer.PrintError("Opção inválida.")
		}
	}
}

func (c *CLI) runWiFiScanner(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s[*] Escaneando redes WiFi...%s\n", view.Cyan, view.Reset)
	
	networks, err := c.wifiService.ScanNetworks()
	if err != nil {
		c.printer.PrintError(err.Error())
		return
	}

	if len(networks) == 0 {
		fmt.Printf("  %s[-] Nenhuma rede WiFi encontrada.%s\n", view.Yellow, view.Reset)
		return
	}

	fmt.Printf("\n  %s%d rede(s) encontrada(s):%s\n", view.Green, len(networks), view.Reset)
	fmt.Printf("  %-30s %-20s %-8s %-6s %-15s %-10s\n", "SSID", "BSSID", "SINAL", "CANAL", "AUTH", "ENCRYPT")
	fmt.Printf("  %-30s %-20s %-8s %-6s %-15s %-10s\n", strings.Repeat("-", 30), strings.Repeat("-", 20), strings.Repeat("-", 8), strings.Repeat("-", 6), strings.Repeat("-", 15), strings.Repeat("-", 10))

	for _, n := range networks {
		ssid := n.SSID
		if len(ssid) > 28 {
			ssid = ssid[:25] + "..."
		}
		if ssid == "" {
			ssid = "<Oculta>"
		}
		
		fmt.Printf("  %-30s %-20s %-8s %-6s %-15s %-10s\n", 
			ssid, n.BSSID, n.Signal, n.Channel, n.Auth, n.Encryption)
	}
	fmt.Println()
}

func (c *CLI) runConfigHashcat(scanner *bufio.Scanner) {
	fmt.Printf("\n  Digite o caminho completo para o hashcat.exe:\n")
	fmt.Printf("  Ex: C:\\Users\\gabri\\Downloads\\hashcat\\hashcat.exe\n")
	fmt.Printf("  %s%scaminho >%s ", view.Bold, view.Magenta, view.Reset)
	
	if !scanner.Scan() {
		return
	}
	
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}
	
	err := c.wifiService.SetHashcatPath(input)
	if err != nil {
		c.printer.PrintError(err.Error())
	} else {
		fmt.Printf("  %s[✓] Caminho configurado com sucesso!%s\n", view.Green, view.Reset)
	}
}

// runHandshakeCapture guia o usuário pela captura do 4-Way Handshake WiFi.
// Detecta ferramentas disponíveis e oferece captura automática (Linux) ou instruções manuais (Windows).
// Após sucesso, exibe claramente o caminho do .hc22000 que o usuário precisa copiar.
func (c *CLI) runHandshakeCapture(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s%s       CAPTURA DE HANDSHAKE — WiFi Auditor               %s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)

	// Verifica se as ferramentas de captura nativa do Linux estão disponíveis
	dumptool, pcapngtool, err := wifi.CheckCaptureTools()
	isWindows := runtime.GOOS == "windows"

	if err != nil && !isWindows {
		// Linux sem ferramentas — exibe guia manual
		fmt.Printf("\n  %s[!] %s%s\n", view.Yellow, err.Error(), view.Reset)
		fmt.Printf("  %s[*] Exibindo guia de captura manual...%s\n\n", view.Cyan, view.Reset)
		fmt.Println(wifi.GetCaptureInstructions())
		
		// Oferece conversão se o usuário já tem o .pcapng
		fmt.Printf("\n  %sVocê já tem um arquivo .pcapng capturado para converter? (s/n):%s ", view.Bold, view.Reset)
		if !scanner.Scan() {
			return
		}
		resp := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if resp == "s" || resp == "y" {
			c.runConvertPcapng(scanner)
		}
		return
	}

	// Ferramentas disponíveis ou Windows
	if isWindows {
		fmt.Printf("\n  %s[✓] Captura nativa Windows (via Npcap) ativada%s\n", view.Green, view.Reset)
	} else {
		fmt.Printf("\n  %s[✓] hcxdumptool: %s%s\n", view.Green, dumptool, view.Reset)
		fmt.Printf("  %s[✓] hcxpcapngtool: %s%s\n", view.Green, pcapngtool, view.Reset)
	}

	for {
		fmt.Printf("\n  %s──────────────────────────────────────────────────────────%s\n", view.Cyan, view.Reset)
		if isWindows {
			fmt.Printf("  %s[ 1 ]%s 📡 Capturar Handshake (Nativo Windows via Npcap)\n", view.Yellow, view.Reset)
		} else {
			fmt.Printf("  %s[ 1 ]%s 📡 Capturar Handshake (hcxdumptool automático)\n", view.Yellow, view.Reset)
		}
		fmt.Printf("  %s[ 2 ]%s 🔄 Converter .pcap/.pcapng → .hc22000 (já tenho a captura)\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 3 ]%s 📖 Exibir guia de captura manual\n", view.Yellow, view.Reset)
		fmt.Printf("  %s[ 0 ]%s 🔙 Voltar\n", view.Red, view.Reset)
		fmt.Printf("  %s──────────────────────────────────────────────────────────%s\n", view.Cyan, view.Reset)
		fmt.Printf("  %s%scaptura >%s ", view.Bold, view.Cyan, view.Reset)

		if !scanner.Scan() {
			return
		}
		input := strings.TrimSpace(scanner.Text())

		switch input {
		case "0", "voltar":
			return
		case "1":
			c.runAutomaticCapture(scanner)
		case "2":
			c.runConvertPcapng(scanner)
		case "3":
			fmt.Println(wifi.GetCaptureInstructions())
		default:
			c.printer.PrintError("Opção inválida.")
		}
	}
}

// runAutomaticCapture executa hcxdumptool automaticamente para capturar o handshake.
func (c *CLI) runAutomaticCapture(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s[*] Detectando interfaces WiFi...%s\n", view.Cyan, view.Reset)
	
	isWindows := runtime.GOOS == "windows"
	var selectedIfaceName string
	var selectedIfaceDesc string

	if isWindows {
		interfaces, err := wifi.ListPcapInterfaces()
		if err != nil || len(interfaces) == 0 {
			c.printer.PrintError(fmt.Sprintf("Erro ao listar interfaces pcap: %v", err))
			return
		}
		
		fmt.Printf("  %sInterfaces disponíveis (Npcap):%s\n", view.Green, view.Reset)
		for i, iface := range interfaces {
			desc := iface.Description
			if desc == "" {
				desc = iface.Name
			}
			fmt.Printf("  %s[ %d ]%s %s\n", view.Yellow, i+1, view.Reset, desc)
		}
		fmt.Printf("  %sEscolha a interface (número):%s ", view.Bold, view.Reset)
		
		if !scanner.Scan() {
			return
		}
		ifaceInput := strings.TrimSpace(scanner.Text())
		var ifaceIdx int
		fmt.Sscanf(ifaceInput, "%d", &ifaceIdx)
		if ifaceIdx < 1 || ifaceIdx > len(interfaces) {
			c.printer.PrintError("Interface inválida.")
			return
		}
		selectedIfaceName = interfaces[ifaceIdx-1].Name
		selectedIfaceDesc = interfaces[ifaceIdx-1].Description
		if selectedIfaceDesc == "" {
			selectedIfaceDesc = selectedIfaceName
		}
	} else {
		interfaces, err := wifi.ListMonitorInterfaces()
		if err != nil || len(interfaces) == 0 {
			c.printer.PrintError(fmt.Sprintf("Erro ao listar interfaces: %v", err))
			return
		}
		
		fmt.Printf("  %sInterfaces disponíveis:%s\n", view.Green, view.Reset)
		for i, iface := range interfaces {
			fmt.Printf("  %s[ %d ]%s %s\n", view.Yellow, i+1, view.Reset, iface)
		}
		fmt.Printf("  %sEscolha a interface (número):%s ", view.Bold, view.Reset)
		
		if !scanner.Scan() {
			return
		}
		ifaceInput := strings.TrimSpace(scanner.Text())
		var ifaceIdx int
		fmt.Sscanf(ifaceInput, "%d", &ifaceIdx)
		if ifaceIdx < 1 || ifaceIdx > len(interfaces) {
			c.printer.PrintError("Interface inválida.")
			return
		}
		selectedIfaceName = interfaces[ifaceIdx-1]
		selectedIfaceDesc = selectedIfaceName
	}

	// Gera caminho padrão para o arquivo de captura
	var outputFile string
	if isWindows {
		outputFile = wifi.GenerateDefaultCapturePath("pcap")
	} else {
		outputFile = wifi.GenerateDefaultCapturePath("pcapng")
	}

	fmt.Printf("\n  %s[*] Interface selecionada: %s%s\n", view.Cyan, selectedIfaceDesc, view.Reset)
	fmt.Printf("  %s[*] Arquivo de saída: %s%s\n", view.Cyan, outputFile, view.Reset)

	fmt.Printf("\n  %s%s⚠️  ATENÇÃO:%s\n", view.Bold, view.Yellow, view.Reset)
	fmt.Printf("  %s  • A captura requer privilégios root (sudo)%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s  • A interface será colocada em modo monitor%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s  • Capture por pelo menos 60 segundos para obter handshakes%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s  • Pressione Ctrl+C neste terminal para PARAR a captura%s\n", view.Yellow, view.Reset)
	fmt.Printf("\n  %sIniciar captura? (s/n):%s ", view.Bold, view.Reset)

	if !scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "s" {
		return
	}

	fmt.Printf("\n  %s[🔴 CAPTURANDO...] Ctrl+C para parar%s\n\n", view.Red, view.Reset)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	onOutput := func(line string) {
		if line == "" {
			return
		}
		fmt.Printf("  %s│%s %s\n", view.Cyan, view.Reset, line)
	}

	var err error
	if isWindows {
		err = wifi.RunCaptureGopacket(ctx, selectedIfaceName, outputFile, onOutput)
	} else {
		err = wifi.RunCapture(ctx, selectedIfaceName, outputFile, onOutput)
	}

	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro na captura: %v", err))
		return
	}

	fmt.Printf("\n  %s[✓] Captura finalizada: %s%s\n", view.Green, outputFile, view.Reset)

	// Pergunta se quer converter automaticamente
	fmt.Printf("\n  %sConverter captura para .hc22000 agora? (s/n):%s ", view.Bold, view.Reset)
	if !scanner.Scan() {
		return
	}
	if strings.ToLower(strings.TrimSpace(scanner.Text())) == "s" {
		c.convertAndShowResult(outputFile)
	} else {
		fmt.Printf("\n  %s[*] Para converter depois, use a opção 2 deste menu.%s\n", view.Cyan, view.Reset)
		fmt.Printf("  %s[*] Arquivo capturado salvo em:%s\n", view.Cyan, view.Reset)
		c.printCopyableFilePath(outputFile)
	}
}

// runConvertPcapng converte um arquivo .pcapng existente para .hc22000.
func (c *CLI) runConvertPcapng(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s[*] Conversão de .pcapng → .hc22000%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Digite o caminho do arquivo .pcapng (ou 'voltar'):\n")
	fmt.Printf("  %s%spcapng >%s ", view.Bold, view.Cyan, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	if _, err := os.Stat(input); err != nil {
		c.printer.PrintError(fmt.Sprintf("Arquivo não encontrado: %s", input))
		return
	}

	c.convertAndShowResult(input)
}

// convertAndShowResult converte o .pcapng e exibe o resultado formatado.
func (c *CLI) convertAndShowResult(pcapngFile string) {
	fmt.Printf("\n  %s[*] Convertendo captura para formato Hashcat...%s\n", view.Cyan, view.Reset)

	hc22000File, output, err := wifi.ConvertPcapngToHc22000(pcapngFile)
	
	// Mostra a saída do hcxpcapngtool (contém info sobre handshakes encontrados)
	if output != "" {
		fmt.Printf("\n  %s── Saída do hcxpcapngtool ──%s\n", view.White, view.Reset)
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fmt.Printf("  %s│%s %s\n", view.White, view.Reset, line)
		}
		fmt.Printf("  %s────────────────────────────%s\n", view.White, view.Reset)
	}

	if err != nil {
		c.printer.PrintError(err.Error())
		fmt.Printf("\n  %s[!] Dica: A captura pode não ter pego nenhum 4-Way Handshake.%s\n", view.Yellow, view.Reset)
		fmt.Printf("  %s    Tente capturar por mais tempo ou espere um dispositivo se conectar à rede.%s\n", view.Yellow, view.Reset)
		return
	}

	// === RESULTADO DE SUCESSO — EXIBE O CAMINHO PARA COPIAR ===
	fmt.Printf("\n  %s%s╔══════════════════════════════════════════════════════════════╗%s\n", view.Bold, view.Green, view.Reset)
	fmt.Printf("  %s%s║           ✅ HANDSHAKE CONVERTIDO COM SUCESSO!               ║%s\n", view.Bold, view.Green, view.Reset)
	fmt.Printf("  %s%s╠══════════════════════════════════════════════════════════════╣%s\n", view.Bold, view.Green, view.Reset)
	fmt.Printf("  %s%s║                                                              ║%s\n", view.Bold, view.Green, view.Reset)
	fmt.Printf("  %s%s║  📋 COPIE O CAMINHO ABAIXO para usar no Brute Force          ║%s\n", view.Bold, view.Green, view.Reset)
	fmt.Printf("  %s%s║     ou Dicionário (opções 2 e 3 do menu WiFi):               ║%s\n", view.Bold, view.Green, view.Reset)
	fmt.Printf("  %s%s║                                                              ║%s\n", view.Bold, view.Green, view.Reset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════════╝%s\n", view.Bold, view.Green, view.Reset)

	c.printCopyableFilePath(hc22000File)

	fmt.Printf("\n  %s[*] Agora volte ao menu WiFi e escolha:%s\n", view.Cyan, view.Reset)
	fmt.Printf("  %s    → Opção 2 (Brute Force) ou Opção 3 (Dicionário)%s\n", view.Cyan, view.Reset)
	fmt.Printf("  %s    → Cole o caminho acima quando pedir o arquivo .hc22000%s\n", view.Cyan, view.Reset)
}

// printCopyableFilePath exibe o caminho de um arquivo de forma destacada e fácil de copiar.
func (c *CLI) printCopyableFilePath(filePath string) {
	fmt.Printf("\n  %s┌──────────────────────────────────────────────────────────────┐%s\n", view.Yellow, view.Reset)
	fmt.Printf("  %s│%s  %s%s%s%s\n", view.Yellow, view.Reset, view.Bold, filePath, view.Reset, "")
	fmt.Printf("  %s└──────────────────────────────────────────────────────────────┘%s\n", view.Yellow, view.Reset)
}

func (c *CLI) getHandshakeFile(scanner *bufio.Scanner) string {
	fmt.Printf("\n  %s[*] Passo 1: Arquivo de Handshake%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Para quebrar a senha, você precisa ter capturado o 4-Way Handshake antes.\n")
	fmt.Printf("  %s(Não tem? Use a opção 5 do menu WiFi para capturar!)%s\n", view.Yellow, view.Reset)
	fmt.Printf("  Digite o caminho do arquivo .hc22000 (ou 'voltar'):\n")
	fmt.Printf("  %s%shandshake >%s ", view.Bold, view.Magenta, view.Reset)
	
	if !scanner.Scan() {
		return ""
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "voltar" {
		return ""
	}
	
	if _, err := os.Stat(input); err != nil {
		c.printer.PrintError(fmt.Sprintf("Arquivo não encontrado: %s", input))
		return ""
	}
	
	return input
}

func (c *CLI) runWiFiBruteForce(scanner *bufio.Scanner) {
	hashcatPath := c.wifiService.GetHashcatPath()
	if hashcatPath == "" {
		c.printer.PrintError("Hashcat não configurado. Use a opção 4 primeiro.")
		return
	}

	handshakeFile := c.getHandshakeFile(scanner)
	if handshakeFile == "" {
		return
	}

	config := domain.HashcatConfig{
		BinaryPath:    hashcatPath,
		HandshakeFile: handshakeFile,
		AttackMode:    domain.HashcatBruteForce,
	}

	fmt.Printf("\n  %s[*] Passo 2: Configurar Charset (Caracteres permitidos)%s\n", view.Cyan, view.Reset)
	fmt.Printf("  [ 1 ] Apenas Números (0-9)\n")
	fmt.Printf("  [ 2 ] Letras Minúsculas (a-z)\n")
	fmt.Printf("  [ 3 ] Letras (a-zA-Z) + Números (0-9)\n")
	fmt.Printf("  [ 4 ] Todos os caracteres (a-zA-Z0-9!@#$)\n")
	fmt.Printf("  %s%scharset >%s ", view.Bold, view.Magenta, view.Reset)
	
	if !scanner.Scan() { return }
	charsetOpt := strings.TrimSpace(scanner.Text())
	
	switch charsetOpt {
	case "1":
		config.Charset.Digits = true
	case "2":
		config.Charset.Lower = true
	case "3":
		config.Charset.Digits = true
		config.Charset.Lower = true
		config.Charset.Upper = true
	case "4":
		config.Charset.AllPrint = true
	default:
		c.printer.PrintError("Opção inválida, usando padrão (Números)")
		config.Charset.Digits = true
	}

	fmt.Printf("\n  %s[*] Passo 3: Comprimento da Senha%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Mínimo (padrão 8): ")
	if !scanner.Scan() { return }
	minInput := strings.TrimSpace(scanner.Text())
	if minInput == "" { minInput = "8" }
	fmt.Sscanf(minInput, "%d", &config.MinLength)
	
	fmt.Printf("  Máximo (padrão 12): ")
	if !scanner.Scan() { return }
	maxInput := strings.TrimSpace(scanner.Text())
	if maxInput == "" { maxInput = "12" }
	fmt.Sscanf(maxInput, "%d", &config.MaxLength)
	
	if config.MinLength < 8 { config.MinLength = 8 }
	if config.MaxLength < config.MinLength { config.MaxLength = config.MinLength }

	fmt.Printf("\n  %s[*] Configuração concluída:%s\n", view.Green, view.Reset)
	fmt.Printf("  Charset: %s\n", wifi.GetCharsetDescription(config.Charset))
	fmt.Printf("  Tamanho: %d a %d caracteres\n", config.MinLength, config.MaxLength)
	
	estimativa := wifi.EstimateCombinations(config.Charset, config.MinLength, config.MaxLength)
	fmt.Printf("  Combinações Estimadas: ~%d\n", estimativa)
	
	fmt.Printf("\n  %sIniciar ataque? (s/n):%s ", view.Bold, view.Reset)
	if !scanner.Scan() { return }
	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "s" {
		return
	}

	c.executeHashcat(config)
}

func (c *CLI) runWiFiDictionary(scanner *bufio.Scanner) {
	hashcatPath := c.wifiService.GetHashcatPath()
	if hashcatPath == "" {
		c.printer.PrintError("Hashcat não configurado. Use a opção 4 primeiro.")
		return
	}

	handshakeFile := c.getHandshakeFile(scanner)
	if handshakeFile == "" {
		return
	}
	
	fmt.Printf("\n  %s[*] Passo 2: Arquivo de Wordlist%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Digite o caminho para o arquivo .txt com as senhas:\n")
	fmt.Printf("  %s%swordlist >%s ", view.Bold, view.Magenta, view.Reset)
	
	if !scanner.Scan() { return }
	wordlist := strings.TrimSpace(scanner.Text())
	
	if _, err := os.Stat(wordlist); err != nil {
		c.printer.PrintError(fmt.Sprintf("Arquivo não encontrado: %s", wordlist))
		return
	}
	
	config := domain.HashcatConfig{
		BinaryPath:    hashcatPath,
		HandshakeFile: handshakeFile,
		AttackMode:    domain.HashcatDictionary,
		WordlistPath:  wordlist,
	}
	
	c.executeHashcat(config)
}

func (c *CLI) executeHashcat(config domain.HashcatConfig) {
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Magenta, view.Reset)
	fmt.Printf("  %s%s       WIFI AUDITOR — HASHCAT GPU CRACKING                %s\n", view.Bold, view.Magenta, view.Reset)
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Magenta, view.Reset)
	fmt.Printf("  %s[*] Iniciando Hashcat...%s\n", view.Cyan, view.Reset)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	onOutput := func(line string) {
		// Filtra linhas vazias ou muito longas (hashes crus)
		if line == "" || len(line) > 150 {
			return
		}
		
		// Coloriza métricas importantes
		if strings.HasPrefix(line, "Speed.") {
			fmt.Printf("  %s%s%s\n", view.Yellow, line, view.Reset)
		} else if strings.HasPrefix(line, "Progress") || strings.HasPrefix(line, "Time.") {
			fmt.Printf("  %s%s%s\n", view.Cyan, line, view.Reset)
		} else if strings.Contains(line, ":") && !strings.Contains(line, " ") {
			// Possível hit (senha)
			fmt.Printf("  %s%s%s\n", view.Green, line, view.Reset)
		} else {
			fmt.Printf("  %s\n", line)
		}
	}

	result, err := wifi.RunHashcat(ctx, config, onOutput)
	
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Magenta, view.Reset)
	
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro ao executar: %v", err))
		return
	}
	
	if result.Found {
		fmt.Printf("  %s[🏆 SUCESSO] Senha Quebrada!%s\n", view.Bold+view.Green, view.Reset)
		fmt.Printf("  %sSENHA:%s %s%s%s\n", view.Yellow, view.Reset, view.Bold, result.Password, view.Reset)
	} else if result.Status == "Exhausted" {
		fmt.Printf("  %s[❌ FALHA] Espaço de busca esgotado. Senha não encontrada.%s\n", view.Red, view.Reset)
	} else if result.Status == "Aborted" {
		fmt.Printf("  %s[⏸️ ABORTADO] Execução cancelada.%s\n", view.Yellow, view.Reset)
	} else {
		fmt.Printf("  %s[!] Execução finalizada com status: %s%s\n", view.White, result.Status, view.Reset)
	}
	
	if result.TimeElapsed != "" {
		fmt.Printf("  %sTempo Decorrido:%s %s\n", view.Cyan, view.Reset, result.TimeElapsed)
	}
	
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n\n", view.Bold, view.Magenta, view.Reset)
}
