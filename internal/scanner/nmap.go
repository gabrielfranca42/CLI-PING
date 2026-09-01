package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
)

// IsNmapInstalled verifica se o executável do nmap está disponível no sistema.
// Só retorna true se estivermos no Linux e o nmap estiver no PATH.
func IsNmapInstalled() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("nmap")
	return err == nil
}

// NmapOSScan executa nmap -O para tentar descobrir o Sistema Operacional.
// Retorna o nome do SO e o nível de confiança (0-100).
func NmapOSScan(ip string) (string, int, error) {
	if runtime.GOOS != "linux" {
		return "", 0, fmt.Errorf("nmap só suportado no linux")
	}

	cmd := exec.Command("sudo", "nmap", "-O", "--osscan-guess", "-T4", "--max-os-tries", "1", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", 0, fmt.Errorf("nmap falhou: %v", err)
	}

	outStr := string(output)

	// Busca por "Aggressive OS guesses: Linux 6.1 (98%)"
	reAggressive := regexp.MustCompile(`Aggressive OS guesses: ([^,]+) \((\d+)%\)`)
	matches := reAggressive.FindStringSubmatch(outStr)
	if len(matches) == 3 {
		confidence := 0
		fmt.Sscanf(matches[2], "%d", &confidence)
		return matches[1], confidence, nil
	}

	// Busca por "Running: Linux 6.X"
	reRunning := regexp.MustCompile(`Running: (.+)`)
	runningMatches := reRunning.FindStringSubmatch(outStr)
	if len(runningMatches) == 2 {
		return runningMatches[1], 95, nil // Consideramos 95% de confiança
	}

	// Busca por "Running (JUST GUESSING): Linux 6.X (95%)"
	reGuessing := regexp.MustCompile(`Running \(JUST GUESSING\): ([^ ]+) \(\d+%\)`)
	guessMatches := reGuessing.FindStringSubmatch(outStr)
	if len(guessMatches) == 2 {
		return guessMatches[1], 85, nil
	}

	return "", 0, fmt.Errorf("não foi possível classificar a saída do nmap")
}

// NmapDeepScan realiza uma varredura completa extrema usando -sV, -O e -p- (MitM alvo único).
func NmapDeepScan(ip string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("nmap só suportado no linux")
	}

	// Escaneia as principais portas (--top-ports 1000), Detecta Serviço (-sV) e SO (-O)
	cmd := exec.Command("sudo", "nmap", "-O", "-sV", "-T4", "--top-ports", "1000", "--max-os-tries", "2", ip)
	
	var outBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)
	
	err := cmd.Run()
	if err != nil {
		return outBuf.String(), fmt.Errorf("erro executando nmap: %v", err)
	}

	return outBuf.String(), nil
}

// NmapFastDeepScan realiza uma varredura focada e mais rápida nas portas mais vitais,
// ideal para escaneamento em lote (a partir de logs).
func NmapFastDeepScan(ip string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("nmap só suportado no linux")
	}

	// Escaneia top 100 portas, Detecta Serviço (-sV), SO (-O), ignora ping bloqueado (-Pn) e roda scripts
	cmd := exec.Command("sudo", "nmap", "-Pn", "-O", "-sV", "-T4", "--top-ports", "100", "--script=vuln,discovery", "--host-timeout", "2m", "--max-os-tries", "1", ip)
	
	var outBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &outBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)

	err := cmd.Run()
	if err != nil {
		return outBuf.String(), fmt.Errorf("erro executando nmap: %v", err)
	}

	return outBuf.String(), nil
}

