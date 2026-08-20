package cli

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/gabrifranca/cli_ping/internal/osint"
	"github.com/gabrifranca/cli_ping/view"
)

func (c *CLI) runOSINTMenu(scanner *bufio.Scanner) {
	for {
		provider := c.osintService.ActiveProvider()

		fmt.Printf("\n  %s%s--- OSINT Recon ---%s\n", view.Bold, view.Cyan, view.Reset)
		fmt.Printf("  %s[*] Provedor Atual: %s[%s]%s (Pressione 'T' para alternar)%s\n", view.Dim, view.Cyan, provider.Name(), view.Dim, view.Reset)

		if provider.RequiresAPIKey() {
			if provider.HasAPIKey() {
				fmt.Printf("  %s[*] API Key: Configurada ✓%s\n", view.Green, view.Reset)
			} else {
				fmt.Printf("  %s[!] API Key: Não configurada (configure na opção 4)%s\n", view.Yellow, view.Reset)
			}
		} else {
			fmt.Printf("  %s[*] API Key: Opcional / Gratuito ✓%s\n", view.Green, view.Reset)
		}

		submenu := `  %s[ 1 ]%s Host Lookup (IP → portas, serviços, vulns)
  %s[ 2 ]%s Search (Busca Global de Banners/Vazamentos)
  %s[ 3 ]%s Reverse DNS (Nativo/Gratuito)
  %s[ 4 ]%s Configurar API Keys
  %s[ 0 ]%s Voltar
`
		fmt.Printf(submenu,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Cyan, view.Reset,
			view.Red, view.Reset,
		)
		fmt.Printf("  %s%sosint > %s", view.Bold, view.Cyan, view.Reset)

		if !scanner.Scan() {
			return
		}
		input := strings.TrimSpace(scanner.Text())

		if strings.ToLower(input) == "t" {
			c.osintService.ToggleProvider()
			continue
		}

		switch input {
		case "0", "voltar":
			return
		case "1":
			c.runOSINTHostLookup(scanner)
		case "2":
			c.runOSINTSearch(scanner)
		case "3":
			c.runOSINTReverseDNS(scanner)
		case "4":
			c.runOSINTConfigKey(scanner)
		default:
			c.printer.PrintError("Opção inválida.")
		}
	}
}

func (c *CLI) requireOSINTKey() bool {
	p := c.osintService.ActiveProvider()
	if p.RequiresAPIKey() && !p.HasAPIKey() {
		c.printer.PrintError(fmt.Sprintf("%s requer API Key. Use a opção 4.", p.Name()))
		return false
	}
	return true
}

func (c *CLI) runOSINTHostLookup(scanner *bufio.Scanner) {
	if !c.requireOSINTKey() {
		return
	}

	fmt.Printf("\n  %s[*] OSINT Host Lookup%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Digite o IP do alvo (ex: 8.8.8.8) ou 'voltar':\n")
	fmt.Printf("  %s%sip > %s", view.Bold, view.Cyan, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	// Remove a porta caso o usuário tenha colado algo como "ip:porta"
	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		input = parts[0]
	}

	fmt.Printf("\n  %s[*] Consultando %s via %s ...%s\n", view.Yellow, input, c.osintService.ActiveProvider().Name(), view.Reset)

	result, err := c.osintService.HostLookup(input)
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro: %v", err))
		return
	}

	c.printOSINTHostResult(result)
}

func (c *CLI) printOSINTHostResult(result *osint.OSINTHostResult) {
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)
	fmt.Printf("  %s%s       %s HOST LOOKUP — %s%s\n", view.Bold, view.Cyan, strings.ToUpper(result.Provider), result.IP, view.Reset)
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Cyan, view.Reset)

	if result.Organization != "" {
		fmt.Printf("  %sOrganização:%s  %s\n", view.White, view.Reset, result.Organization)
	}
	if result.Country != "" {
		fmt.Printf("  %sPaís:%s         %s\n", view.White, view.Reset, result.Country)
	}

	if len(result.Tags) > 0 {
		fmt.Printf("  %sTags:%s         %s\n", view.White, view.Reset, strings.Join(result.Tags, ", "))
	}

	if len(result.Services) > 0 {
		fmt.Printf("\n  %s%s── Serviços Detectados ──%s\n", view.Bold, view.Yellow, view.Reset)
		for _, s := range result.Services {
			fmt.Printf("  %s├─ Porta %d/%s%s\n", view.Cyan, s.Port, s.Transport, view.Reset)
			fmt.Printf("  %s│  Produto: %s%s %s%s\n", view.Cyan, view.Green, s.Product, s.Version, view.Reset)
		}
	}

	if len(result.Vulns) > 0 {
		fmt.Printf("\n  %s%s── Vulnerabilidades / Vazamentos (%d) ──%s\n", view.Bold, view.Red, len(result.Vulns), view.Reset)
		for _, v := range result.Vulns {
			fmt.Printf("  %s  🔴 [%s] %s%s\n", view.Red, v.Severity, v.ID, view.Reset)
			if v.Description != "" {
				fmt.Printf("  %s      %s%s\n", view.Dim, v.Description, view.Reset)
			}
		}
	}

	fmt.Printf("  %s══════════════════════════════════════════════════════════%s\n\n", view.Cyan, view.Reset)
}

func (c *CLI) runOSINTSearch(scanner *bufio.Scanner) {
	if !c.requireOSINTKey() {
		return
	}

	fmt.Printf("\n  %s[*] OSINT Busca Global%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Digite o termo de busca (ex: Apache, Nginx, admin):\n")
	fmt.Printf("  %s%squery > %s", view.Bold, view.Cyan, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	fmt.Printf("\n  %s[*] Buscando por '%s' via %s ...%s\n", view.Yellow, input, c.osintService.ActiveProvider().Name(), view.Reset)
	result, err := c.osintService.Search(input, 1)
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro: %v", err))
		return
	}

	fmt.Printf("\n  %s%s── Resultados Encontrados: %d ──%s\n", view.Bold, view.Cyan, result.Total, view.Reset)
	for i, m := range result.Matches {
		info := m.Product
		if info == "" {
			info = "Desconhecido"
		}
		country := m.Country
		if country == "" {
			country = "N/A"
		}

		fmt.Printf("  %s[%d] %s%s%s:%d\n", view.Yellow, i+1, view.Bold, m.IP, view.Reset, m.Port)
		fmt.Printf("      %sProduto:%s %s | %sPaís:%s %s\n", view.Cyan, view.Reset, info, view.Cyan, view.Reset, country)

		if m.Banner != "" {
			banner := strings.TrimSpace(m.Banner)
			if len(banner) > 80 {
				banner = banner[:77] + "..."
			}
			banner = strings.ReplaceAll(banner, "\n", " ")
			fmt.Printf("      %sBanner:%s  %s%s%s\n", view.Cyan, view.Reset, view.Dim, banner, view.Reset)
		}
	}
	fmt.Println()
}

func (c *CLI) runOSINTReverseDNS(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s[*] OSINT Reverse DNS (Nativo)%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Digite os IPs separados por espaço:\n")
	fmt.Printf("  %s%sips > %s", view.Bold, view.Cyan, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	ips := strings.Fields(input)
	fmt.Printf("\n  %s[*] Consultando %d IP(s)...%s\n", view.Yellow, len(ips), view.Reset)

	results := c.osintService.ReverseDNS(ips)
	for ip, names := range results {
		if len(names) > 0 {
			fmt.Printf("  %s%s%s → %s\n", view.Green, ip, view.Reset, strings.Join(names, ", "))
		} else {
			fmt.Printf("  %s%s%s → (sem registros)\n", view.Yellow, ip, view.Reset)
		}
	}
	fmt.Println()
}

func (c *CLI) runOSINTConfigKey(scanner *bufio.Scanner) {
	p := c.osintService.ActiveProvider()
	fmt.Printf("\n  %s[*] Configurar API Key: %s%s\n", view.Cyan, p.Name(), view.Reset)
	fmt.Printf("  Cole a API Key (ou 'voltar'):\n")
	fmt.Printf("  %s%skey > %s", view.Bold, view.Cyan, view.Reset)

	if !scanner.Scan() {
		return
	}
	input := strings.TrimSpace(scanner.Text())
	if input == "" || input == "voltar" {
		return
	}

	p.SetAPIKey(input)
	err := c.osintService.SaveAPIKey(p.Name(), input)
	if err != nil {
		c.printer.PrintError(fmt.Sprintf("Erro ao salvar: %v", err))
		return
	}
	fmt.Printf("  %s[✓] API Key para %s configurada e salva!%s\n", view.Green, p.Name(), view.Reset)
}
