package wifi

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/gabrifranca/cli_ping/internal/domain"
)

// CheckMDK4 verifica se a ferramenta mdk4 está instalada.
func CheckMDK4() (string, error) {
	path, err := exec.LookPath("mdk4")
	if err != nil {
		return "", fmt.Errorf("mdk4 não encontrado. Instale com: sudo apt install mdk4")
	}
	return path, nil
}

// RunMDK4 executa o ataque usando MDK4.
func RunMDK4(ctx context.Context, config domain.MDK4Config, onOutput func(string)) (domain.MDK4Result, error) {
	start := time.Now()

	mdk4Path, err := CheckMDK4()
	if err != nil {
		return domain.MDK4Result{}, err
	}

	// Fixa o canal na interface se necessário
	if config.Channel > 0 {
		if err := SetChannel(config.Interface, config.Channel); err != nil {
			if onOutput != nil {
				onOutput(fmt.Sprintf("[!] Aviso: Falha ao fixar canal: %v", err))
			}
		}
	}

	args := []string{config.Interface, config.Mode}

	// Opções específicas para os modos
	if config.Mode == "d" {
		// Deauth agressivo
		if config.TargetBSSID != "" {
			args = append(args, "-B", config.TargetBSSID)
		}
	} else if config.Mode == "a" {
		// Auth Flood
		if config.TargetBSSID != "" {
			args = append(args, "-a", config.TargetBSSID)
		}
	}

	cmd := exec.CommandContext(ctx, "sudo", append([]string{mdk4Path}, args...)...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return domain.MDK4Result{}, fmt.Errorf("erro ao criar pipe stdout: %w", err)
	}

	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return domain.MDK4Result{}, fmt.Errorf("erro ao iniciar mdk4: %w", err)
	}

	if onOutput != nil {
		onOutput(fmt.Sprintf("[*] Executando: sudo %s %v", mdk4Path, args))
		onOutput("[*] Pressione Ctrl+C para parar...")
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if onOutput != nil {
			onOutput("  " + line)
		}
	}

	err = cmd.Wait()

	result := domain.MDK4Result{
		Duration: time.Since(start),
	}

	if err != nil {
		if ctx.Err() != nil {
			result.Status = "Aborted"
			result.Error = "Operação cancelada pelo usuário"
		} else {
			result.Status = "Error"
			result.Error = err.Error()
		}
	} else {
		result.Status = "Completed"
	}

	return result, nil
}
