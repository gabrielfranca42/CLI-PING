package controller

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gabrifranca/cli_ping/model"
	"github.com/gabrifranca/cli_ping/service"
	"github.com/gabrifranca/cli_ping/view"
)

// PingController orchestrates the ping operations between service and view.
type PingController struct {
	service      *service.PingService
	extraService *service.ExtraService
	printer      *view.Printer
}

// NewPingController creates a new PingController instance.
func NewPingController() *PingController {
	return &PingController{
		service:      service.NewPingService(),
		extraService: service.NewExtraService(),
		printer:      view.NewPrinter(),
	}
}

// RunInteractive starts the interactive REPL mode.
func (c *PingController) RunInteractive() {
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

// printMainMenu shows the available commands in interactive mode.
func (c *PingController) printMainMenu() {
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

func (c *PingController) runPingMenu(scanner *bufio.Scanner) {
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
		opts := model.DefaultPingOptions()
		result := c.service.CheckTLS(tokens[1], opts.Timeout)
		c.printer.PrintResult(result)

	default:
		// Treat as a URL directly
		opts := model.DefaultPingOptions()
		result := c.service.Ping(input, opts)
		c.printer.PrintResult(result)
	}
}

func (c *PingController) runPortScanMenu(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s%s--- Port Scanner ---%s\n", view.Bold, view.Cyan, view.Reset)
	submenu := `  %s[ 1 ]%s Escanear porta em host remoto
  %s[ 2 ]%s Escanear portas locais (localhost)
  %s[ 3 ]%s Escanear dispositivos na rede WiFi
  %s[ 0 ]%s Voltar
`
	fmt.Printf(submenu,
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
	default:
		c.printer.PrintError("Opção inválida.")
	}
}

func (c *PingController) runRemotePortScan(scanner *bufio.Scanner) {
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

func (c *PingController) runLocalPortScan(scanner *bufio.Scanner) {
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
		name := service.PortNames[port]
		if name != "" {
			fmt.Printf("  %s✓ Porta %-5d (%s)%s\n", view.Green, port, name, view.Reset)
		} else {
			fmt.Printf("  %s✓ Porta %d%s\n", view.Green, port, view.Reset)
		}
	}

	fmt.Printf("\n  %s%d porta(s) aberta(s) em %v%s\n\n",
		view.White, len(openPorts), elapsed.Round(time.Millisecond), view.Reset)
}

func (c *PingController) runNetworkScan(scanner *bufio.Scanner) {
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
	c.printer.PrintInfo(fmt.Sprintf("Escaneando 254 hosts com %d portas comuns ...\n", len(service.CommonPorts)))

	startTime := time.Now()

	onFound := func(host model.NetworkHost) {
		portStrs := []string{}
		for _, p := range host.OpenPorts {
			name := service.PortNames[p]
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

	results := c.extraService.NetworkScan(base, service.CommonPorts, onFound)
	elapsed := time.Since(startTime)

	if len(results) == 0 {
		fmt.Printf("\n  %sNenhum dispositivo encontrado.%s\n\n", view.Yellow, view.Reset)
		return
	}

	fmt.Printf("\n  %s%d dispositivo(s) encontrado(s) em %v%s\n\n",
		view.White, len(results), elapsed.Round(time.Millisecond), view.Reset)
}

func (c *PingController) runDNSMenu(scanner *bufio.Scanner) {
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

func (c *PingController) runLoadTestMenu(scanner *bufio.Scanner) {
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

func (c *PingController) runJWTMenu(scanner *bufio.Scanner) {
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
func (c *PingController) executePing(args []string, opts model.PingOptions, jsonOutput bool) {
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
func (c *PingController) RunPing(args []string, opts model.PingOptions, jsonOutput bool) {
	if len(args) == 0 {
		c.printer.PrintError("no URL(s) provided. Usage: cli-ping ping <url> [url2] ...")
		os.Exit(1)
	}

	c.printer.PrintBanner()
	c.executePing(args, opts, jsonOutput)
}

// RunCheck handles the "check" subcommand for TLS verification (non-interactive).
func (c *PingController) RunCheck(args []string, opts model.PingOptions) {
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
func (c *PingController) RunHelp() {
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

// ParseAndRun parses CLI arguments and routes to the appropriate handler.
func (c *PingController) ParseAndRun() {
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

// parseFlags extracts flags and positional arguments from CLI args.
func (c *PingController) parseFlags(args []string) (model.PingOptions, []string, bool) {
	opts := model.DefaultPingOptions()
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
