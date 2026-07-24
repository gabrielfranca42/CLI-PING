package wifi

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gabrifranca/cli_ping/internal/domain"
)

// BuildMask constrói a máscara do hashcat a partir do charset e comprimento configurados.
// Ex: charset{Digits:true, Lower:true} com length=10 → "?1?1?1?1?1?1?1?1?1?1" + custom charset "-1 ?d?l"
func BuildMask(charset domain.HashcatCharset, length int) (mask string, customCharset string) {
	if charset.AllPrint {
		// ?a = todos os caracteres printáveis
		for i := 0; i < length; i++ {
			mask += "?a"
		}
		return mask, ""
	}

	// Constrói um charset customizado combinando os tipos selecionados
	cs := ""
	if charset.Digits {
		cs += "?d"
	}
	if charset.Lower {
		cs += "?l"
	}
	if charset.Upper {
		cs += "?u"
	}
	if charset.Special {
		cs += "?s"
	}

	if cs == "" {
		// Fallback para dígitos se nada selecionado
		cs = "?d"
	}

	// Se só tem um tipo, usa direto sem custom charset
	typeCount := 0
	if charset.Digits {
		typeCount++
	}
	if charset.Lower {
		typeCount++
	}
	if charset.Upper {
		typeCount++
	}
	if charset.Special {
		typeCount++
	}

	if typeCount == 1 {
		for i := 0; i < length; i++ {
			mask += cs
		}
		return mask, ""
	}

	// Usa charset customizado -1
	customCharset = cs
	for i := 0; i < length; i++ {
		mask += "?1"
	}
	return mask, customCharset
}

// BuildHashcatArgs constrói os argumentos de linha de comando para o hashcat.
func BuildHashcatArgs(config domain.HashcatConfig) []string {
	args := []string{
		"-m", "22000", // WPA-PBKDF2-PMKID+EAPOL
		"-a", fmt.Sprintf("%d", config.AttackMode),
		"--status",            // Exibe status periódico
		"--status-timer", "5", // A cada 5 segundos
		"-O",                  // Kernels otimizados
		"--quiet",             // Reduz ruído na saída
	}

	if config.AttackMode == domain.HashcatBruteForce {
		// Modo Brute Force (Mask Attack)
		mask, customCharset := BuildMask(config.Charset, config.MaxLength)

		if customCharset != "" {
			args = append(args, "-1", customCharset)
		}

		// Incremento automático para testar múltiplos comprimentos
		if config.MinLength < config.MaxLength {
			args = append(args,
				"--increment",
				"--increment-min", fmt.Sprintf("%d", config.MinLength),
				"--increment-max", fmt.Sprintf("%d", config.MaxLength),
			)
		}

		args = append(args, config.HandshakeFile, mask)

	} else if config.AttackMode == domain.HashcatDictionary {
		// Modo Dicionário (Wordlist)
		if config.RulesFile != "" {
			args = append(args, "-r", config.RulesFile)
		}
		args = append(args, config.HandshakeFile, config.WordlistPath)
	}

	return args
}

// RunHashcat executa o hashcat como subprocesso e transmite a saída em tempo real.
// O callback onOutput é chamado para cada linha da saída, permitindo exibição no terminal.
// Retorna o resultado final com a senha (se encontrada) ao encerrar.
func RunHashcat(ctx context.Context, config domain.HashcatConfig, onOutput func(line string)) (*domain.HashcatResult, error) {
	// Verifica se o binário existe
	if _, err := os.Stat(config.BinaryPath); err != nil {
		return nil, fmt.Errorf("hashcat não encontrado em: %s", config.BinaryPath)
	}

	// Verifica se o arquivo de handshake existe
	if _, err := os.Stat(config.HandshakeFile); err != nil {
		return nil, fmt.Errorf("arquivo de handshake não encontrado: %s", config.HandshakeFile)
	}

	args := BuildHashcatArgs(config)

	// O hashcat precisa rodar no seu próprio diretório para encontrar os kernels OpenCL
	hashcatDir := filepath.Dir(config.BinaryPath)

	cmd := exec.CommandContext(ctx, config.BinaryPath, args...)
	cmd.Dir = hashcatDir

	// Captura stdout e stderr juntos
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("erro ao criar pipe stdout: %w", err)
	}

	cmd.Stderr = cmd.Stdout // Junta stderr no stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("erro ao iniciar hashcat: %w", err)
	}

	result := &domain.HashcatResult{
		Status: "Running",
	}

	// Lê a saída em tempo real
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		// Envia para o callback de exibição
		if onOutput != nil {
			onOutput(line)
		}

		// Parseia informações relevantes da saída
		parseLine(line, result)
	}

	// Aguarda o processo terminar
	err = cmd.Wait()

	// Hashcat exit codes:
	// 0 = cracked
	// 1 = exhausted (testou tudo, não encontrou)
	// 2 = aborted by user
	// -1 / other = error
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			switch exitErr.ExitCode() {
			case 1:
				result.Status = "Exhausted"
			case 2:
				result.Status = "Aborted"
			default:
				result.Status = "Error"
			}
		} else {
			// Contexto cancelado pelo usuário
			if ctx.Err() != nil {
				result.Status = "Aborted"
			} else {
				result.Status = "Error"
			}
		}
	} else {
		if result.Found {
			result.Status = "Cracked"
		} else {
			result.Status = "Exhausted"
		}
	}

	return result, nil
}

// parseLine extrai informações relevantes de uma linha de saída do hashcat.
func parseLine(line string, result *domain.HashcatResult) {
	line = strings.TrimSpace(line)

	// Detecta senha encontrada — formato: "hash:senha" ou linhas com o resultado
	if strings.Contains(line, ":") && !strings.HasPrefix(line, "Session") &&
		!strings.HasPrefix(line, "Status") && !strings.HasPrefix(line, "Hash") &&
		!strings.HasPrefix(line, "Speed") && !strings.HasPrefix(line, "Time") &&
		!strings.HasPrefix(line, "Guess") && !strings.HasPrefix(line, "Progress") &&
		!strings.HasPrefix(line, "Recovered") && !strings.HasPrefix(line, "Restore") &&
		!strings.HasPrefix(line, "Candidates") && !strings.HasPrefix(line, "HWMon") &&
		!strings.HasPrefix(line, "Kernel") && !strings.HasPrefix(line, "Started") &&
		!strings.HasPrefix(line, "Stopped") && !strings.HasPrefix(line, "*") &&
		!strings.HasPrefix(line, "Approach") && !strings.HasPrefix(line, "Watchdog") &&
		!strings.HasPrefix(line, "OpenCL") && !strings.HasPrefix(line, "Initializ") &&
		!strings.HasPrefix(line, "hashcat") && !strings.HasPrefix(line, "Dictionary") &&
		len(line) > 5 {
		// Possível linha com a senha crackeada
		// Formato típico: <hash_completo>:<senha>
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			possiblePassword := parts[len(parts)-1]
			if len(possiblePassword) >= 8 && !strings.Contains(possiblePassword, " ") {
				result.Found = true
				result.Password = possiblePassword
			}
		}
	}

	// Detecta velocidade
	if strings.HasPrefix(line, "Speed.") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result.Speed = strings.TrimSpace(parts[1])
		}
	}

	// Detecta tempo
	if strings.HasPrefix(line, "Time.Estimated") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result.TimeElapsed = strings.TrimSpace(parts[1])
		}
	}
}

// GetCharsetDescription retorna uma descrição legível do charset configurado.
func GetCharsetDescription(charset domain.HashcatCharset) string {
	if charset.AllPrint {
		return "Todos (a-z, A-Z, 0-9, especiais)"
	}

	var parts []string
	if charset.Digits {
		parts = append(parts, "0-9")
	}
	if charset.Lower {
		parts = append(parts, "a-z")
	}
	if charset.Upper {
		parts = append(parts, "A-Z")
	}
	if charset.Special {
		parts = append(parts, "!@#$%...")
	}

	if len(parts) == 0 {
		return "Nenhum (padrão: 0-9)"
	}

	return strings.Join(parts, " + ")
}

// EstimateCombinations calcula o número aproximado de combinações para o charset e comprimento.
func EstimateCombinations(charset domain.HashcatCharset, minLen, maxLen int) uint64 {
	base := uint64(0)
	if charset.AllPrint {
		base = 95 // Todos os printáveis ASCII
	} else {
		if charset.Digits {
			base += 10
		}
		if charset.Lower {
			base += 26
		}
		if charset.Upper {
			base += 26
		}
		if charset.Special {
			base += 33
		}
	}

	if base == 0 {
		base = 10 // fallback
	}

	var total uint64
	for length := minLen; length <= maxLen; length++ {
		combinations := uint64(1)
		for i := 0; i < length; i++ {
			combinations *= base
			// Evita overflow
			if combinations > 1e18 {
				return combinations
			}
		}
		total += combinations
		if total > 1e18 {
			return total
		}
	}

	return total
}
