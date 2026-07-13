package controller

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gabrifranca/cli-ping/model"
	"github.com/gabrifranca/cli-ping/service"
	"github.com/gabrifranca/cli-ping/view"
)

// PingController orchestrates the ping operations between service and view.
type PingController struct {
	service *service.PingService
	printer *view.Printer
}

// NewPingController creates a new PingController instance.
func NewPingController() *PingController {
	return &PingController{
		service: service.NewPingService(),
		printer: view.NewPrinter(),
	}
}

// RunInteractive starts the interactive REPL mode.
func (c *PingController) RunInteractive() {
	c.printer.PrintBanner()
	c.printInteractiveHelp()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Printf("  %s%sajin >%s ", view.Bold, view.Cyan, view.Reset)

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())

		if input == "" {
			continue
		}

		// Parse the input into tokens
		tokens := strings.Fields(input)
		command := strings.ToLower(tokens[0])

		switch command {
		case "exit", "quit", "q":
			fmt.Printf("\n  %s👋 Até mais!%s\n\n", view.Cyan, view.Reset)
			return

		case "help", "h":
			c.printInteractiveHelp()

		case "clear", "cls":
			fmt.Print("\033[H\033[2J")
			c.printer.PrintBanner()

		case "ping":
			if len(tokens) < 2 {
				c.printer.PrintError("informe pelo menos uma URL. Ex: ping google.com")
				continue
			}
			opts, urls, jsonOutput := c.parseFlags(tokens[1:])
			c.executePing(urls, opts, jsonOutput)

		case "check":
			if len(tokens) < 2 {
				c.printer.PrintError("informe uma URL. Ex: check google.com")
				continue
			}
			opts := model.DefaultPingOptions()
			result := c.service.CheckTLS(tokens[1], opts.Timeout)
			c.printer.PrintResult(result)

		default:
			// Treat as a URL directly — the user just typed a URL
			opts := model.DefaultPingOptions()
			result := c.service.Ping(input, opts)
			c.printer.PrintResult(result)
		}
	}
}

// printInteractiveHelp shows the available commands in interactive mode.
func (c *PingController) printInteractiveHelp() {
	help := `  %s%sCOMANDOS DISPONÍVEIS:%s
  ──────────────────────────────────────────────────
  %s<url>%s                        Ping direto em uma URL
  %sping%s <url> [url2] [flags]    Ping com opções
  %scheck%s <url>                  Verificar certificado TLS
  %sclear%s                        Limpar a tela
  %shelp%s                         Mostrar esta ajuda
  %sexit%s                         Sair

  %s%sFLAGS (para o comando ping):%s
  -c <n>       Número de pings     -t <seg>     Timeout
  -i <seg>     Intervalo           --json       Saída JSON
  --no-follow  Não seguir redirects
  ──────────────────────────────────────────────────
`
	fmt.Printf(help,
		view.Bold, view.Cyan, view.Reset,
		view.Yellow, view.Reset,
		view.Green, view.Reset,
		view.Green, view.Reset,
		view.Green, view.Reset,
		view.Green, view.Reset,
		view.Green, view.Reset,
		view.Bold, view.Cyan, view.Reset,
	)
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
