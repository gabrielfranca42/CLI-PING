package view

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/gabrifranca/cli_ping/internal/domain"
)

// Cores ANSI
const (
	Reset   = "\033[0m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
)

// Printer lida com toda a formatação de saída para a CLI.
type Printer struct{}

// NewPrinter cria uma nova instância de Printer.
func NewPrinter() *Printer {
	return &Printer{}
}

// PrintBanner exibe o banner da CLI.
func (p *Printer) PrintBanner() {
	banner := `
       █████╗      ██╗██╗███╗   ██╗
      ██╔══██╗     ██║██║████╗  ██║
      ███████║     ██║██║██╔██╗ ██║
      ██╔══██║██   ██║██║██║╚██╗██║
      ██║  ██║╚█████╔╝██║██║ ╚████║
      ╚═╝  ╚═╝ ╚════╝ ╚═╝╚═╝  ╚═══╝`
	fmt.Printf("%s%s%s\n", Cyan, banner, Reset)
	fmt.Printf("  %s%sService Health Checker v1.0%s\n\n", Dim, White, Reset)
}

// PrintResult exibe um único resultado de ping com cores.
func (p *Printer) PrintResult(result domain.PingResult) {
	statusColor := p.getStatusColor(result.Status)

	fmt.Printf("  %s┌─────────────────────────────────────────────────┐%s\n", Dim, Reset)
	fmt.Printf("  %s│%s %s%-47s%s %s│%s\n", Dim, Reset, Bold, result.URL, Reset, Dim, Reset)
	fmt.Printf("  %s├─────────────────────────────────────────────────┤%s\n", Dim, Reset)

	// Status
	fmt.Printf("  %s│%s  Status:      %s%-35s%s%s│%s\n",
		Dim, Reset, statusColor, result.Status, Reset, Dim, Reset)

	// Código de Status
	if result.StatusCode > 0 {
		fmt.Printf("  %s│%s  HTTP Code:   %-35d%s│%s\n",
			Dim, Reset, result.StatusCode, Dim, Reset)
	}

	// Latência
	fmt.Printf("  %s│%s  Latency:     %-35s%s│%s\n",
		Dim, Reset, result.Latency.Round(1_000_000).String(), Dim, Reset)

	// Ativo
	aliveStr := fmt.Sprintf("%s✗ Offline%s", Red, Reset)
	if result.Alive {
		aliveStr = fmt.Sprintf("%s✓ Online%s", Green, Reset)
	}
	fmt.Printf("  %s│%s  Alive:       %-44s%s│%s\n",
		Dim, Reset, aliveStr, Dim, Reset)

	// Informações TLS
	if !result.TLSExpiry.IsZero() {
		tlsStr := fmt.Sprintf("%s✓ Valid (expires %s)%s", Green, result.TLSExpiry.Format("2006-01-02"), Reset)
		if !result.TLSValid {
			tlsStr = fmt.Sprintf("%s✗ Expired%s", Red, Reset)
		}
		fmt.Printf("  %s│%s  TLS:         %-44s%s│%s\n",
			Dim, Reset, tlsStr, Dim, Reset)
	}

	// Erro
	if result.Error != "" {
		fmt.Printf("  %s│%s  Error:       %s%-35s%s%s│%s\n",
			Dim, Reset, Red, truncate(result.Error, 35), Reset, Dim, Reset)
	}

	// Data e Hora
	fmt.Printf("  %s│%s  Checked at:  %-35s%s│%s\n",
		Dim, Reset, result.Timestamp.Format("15:04:05 02/01/2006"), Dim, Reset)

	fmt.Printf("  %s└─────────────────────────────────────────────────┘%s\n\n", Dim, Reset)
}

// PrintResultsTable exibe múltiplos resultados em um formato de tabela compacta.
func (p *Printer) PrintResultsTable(results []domain.PingResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Cabeçalho
	fmt.Fprintf(w, "  %s%sURL\tSTATUS\tCODE\tLATENCY\tALIVE%s\n", Bold, White, Reset)
	fmt.Fprintf(w, "  %s───\t──────\t────\t───────\t─────%s\n", Dim, Reset)

	for _, r := range results {
		statusColor := p.getStatusColor(r.Status)
		alive := fmt.Sprintf("%s✗%s", Red, Reset)
		if r.Alive {
			alive = fmt.Sprintf("%s✓%s", Green, Reset)
		}
		codeStr := "-"
		if r.StatusCode > 0 {
			codeStr = fmt.Sprintf("%d", r.StatusCode)
		}
		fmt.Fprintf(w, "  %s\t%s%s%s\t%s\t%s\t%s\n",
			r.URL,
			statusColor, r.Status, Reset,
			codeStr,
			r.Latency.Round(1_000_000),
			alive,
		)
	}

	w.Flush()
	fmt.Println()
}

// PrintJSON exibe os resultados em formato JSON.
func (p *Printer) PrintJSON(results []domain.PingResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// PrintRepeatSummary exibe um resumo após pings repetidos.
func (p *Printer) PrintRepeatSummary(results []domain.PingResult) {
	if len(results) == 0 {
		return
	}

	total := len(results)
	alive := 0
	var totalLatency int64
	var minLatency, maxLatency int64

	for i, r := range results {
		if r.Alive {
			alive++
		}
		lat := r.Latency.Milliseconds()
		totalLatency += lat
		if i == 0 || lat < minLatency {
			minLatency = lat
		}
		if lat > maxLatency {
			maxLatency = lat
		}
	}

	avg := totalLatency / int64(total)
	pctAlive := float64(alive) / float64(total) * 100

	fmt.Printf("\n  %s%s── Ping Summary ──────────────────────────────────%s\n", Bold, Cyan, Reset)
	fmt.Printf("  URL:         %s\n", results[0].URL)
	fmt.Printf("  Pings:       %d sent, %s%d up%s, %s%d down%s\n",
		total, Green, alive, Reset, Red, total-alive, Reset)
	fmt.Printf("  Uptime:      %.1f%%\n", pctAlive)
	fmt.Printf("  Latency:     min=%dms  avg=%dms  max=%dms\n", minLatency, avg, maxLatency)
	fmt.Printf("  %s%s──────────────────────────────────────────────────%s\n\n", Bold, Cyan, Reset)
}

// PrintError exibe uma mensagem de erro.
func (p *Printer) PrintError(msg string) {
	fmt.Printf("  %s✗ Error: %s%s\n", Red, msg, Reset)
}

// PrintInfo exibe uma mensagem informativa.
func (p *Printer) PrintInfo(msg string) {
	fmt.Printf("  %sℹ %s%s\n", Cyan, msg, Reset)
}

// getStatusColor retorna a cor ANSI para um determinado status.
func (p *Printer) getStatusColor(status string) string {
	switch status {
	case "UP":
		return Green
	case "REDIRECT":
		return Yellow
	case "CLIENT_ERROR":
		return Magenta
	case "SERVER_ERROR", "DOWN", "ERROR":
		return Red
	case "TLS_OK":
		return Green
	case "TLS_EXPIRED", "TLS_ERROR":
		return Red
	default:
		return White
	}
}

// truncate encurta uma string para o tamanho máximo fornecido.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
