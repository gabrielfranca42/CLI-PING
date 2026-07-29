package sam

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FindParser procura pelas ferramentas de parsing de SAM disponíveis no sistema.
// Retorna o nome da ferramenta encontrada, seu caminho completo, e erro se nenhuma for encontrada.
// Ordem de preferência: secretsdump (Impacket) > samdump2.
func FindParser() (toolName string, toolPath string, err error) {
	// Variantes do secretsdump (Impacket) — a mais completa e confiável
	secretsdumpNames := []string{
		"secretsdump",          // standalone compilado
		"secretsdump.exe",      // Windows standalone
		"impacket-secretsdump", // instalado via pip (Linux/macOS)
		"secretsdump.py",       // script Python direto
	}

	for _, name := range secretsdumpNames {
		if path, lookErr := exec.LookPath(name); lookErr == nil {
			return name, path, nil
		}
	}

	// samdump2 — alternativa mais simples (comum no Kali/Ubuntu)
	if path, lookErr := exec.LookPath("samdump2"); lookErr == nil {
		return "samdump2", path, nil
	}

	return "", "", fmt.Errorf("nenhuma ferramenta de parsing encontrada")
}

// ParseSAMFiles recebe os caminhos dos arquivos SAM e SYSTEM copiados offline
// e extrai os hashes NTLM usando a melhor ferramenta disponível no sistema.
// Os hashes são salvos em um arquivo pronto para o Hashcat (-m 1000).
func ParseSAMFiles(samPath, systemPath, outputDir string) (*SAMDumpResult, error) {
	// Valida se os arquivos existem
	if _, err := os.Stat(samPath); err != nil {
		return nil, fmt.Errorf("arquivo SAM não encontrado: %s", samPath)
	}
	if _, err := os.Stat(systemPath); err != nil {
		return nil, fmt.Errorf("arquivo SYSTEM não encontrado: %s", systemPath)
	}

	// Detecta a ferramenta disponível
	toolName, toolPath, err := FindParser()
	if err != nil {
		return nil, fmt.Errorf("nenhuma ferramenta de dump encontrada.\n\n" +
			"  Instale uma das seguintes:\n" +
			"  • Impacket (recomendado): pip install impacket\n" +
			"  • samdump2 (Linux):       sudo apt install samdump2\n" +
			"  • secretsdump.exe:        baixe standalone em github.com/fortra/impacket\n\n" +
			"  Após instalar, tente novamente")
	}

	// Executa a ferramenta
	var output string
	switch {
	case strings.Contains(toolName, "secretsdump"):
		// impacket-secretsdump -sam <SAM> -system <SYSTEM> LOCAL
		cmd := exec.Command(toolPath, "-sam", samPath, "-system", systemPath, "LOCAL")
		out, cmdErr := cmd.CombinedOutput()
		if cmdErr != nil {
			return nil, fmt.Errorf("erro ao executar %s: %w\nSaída: %s", toolName, cmdErr, string(out))
		}
		output = string(out)

	case toolName == "samdump2":
		// samdump2 <SYSTEM> <SAM>
		cmd := exec.Command(toolPath, systemPath, samPath)
		out, cmdErr := cmd.CombinedOutput()
		if cmdErr != nil {
			return nil, fmt.Errorf("erro ao executar samdump2: %w\nSaída: %s", cmdErr, string(out))
		}
		output = string(out)
	}

	// Parseia a saída para extrair os hashes
	hashes := parseHashOutput(output)
	if len(hashes) == 0 {
		return nil, fmt.Errorf("nenhum hash extraído. Verifique se os arquivos SAM e SYSTEM são válidos e da mesma máquina")
	}

	// Gera os arquivos de saída
	timestamp := time.Now().Format("2006-01-02_15-04-05")

	// Arquivo para Hashcat (só os hashes NTLM, 1 por linha)
	hashFile := filepath.Join(outputDir, fmt.Sprintf("ntlm_hashes_%s.txt", timestamp))
	if err := SaveHashFile(hashes, hashFile); err != nil {
		return nil, fmt.Errorf("erro ao salvar arquivo de hashes: %w", err)
	}

	// Arquivo de referência (formato completo user:rid:lm:ntlm:::)
	dumpFile := filepath.Join(outputDir, fmt.Sprintf("sam_dump_%s.txt", timestamp))
	if err := SaveFullDump(hashes, dumpFile); err != nil {
		// Não é crítico — o hash file é o importante
		dumpFile = ""
	}

	return &SAMDumpResult{
		Hashes:     hashes,
		HashFile:   hashFile,
		DumpFile:   dumpFile,
		TotalUsers: len(hashes),
	}, nil
}

// parseHashOutput processa a saída de texto do secretsdump/samdump2 e extrai os hashes NTLM.
func parseHashOutput(output string) []NTLMHash {
	var hashes []NTLMHash
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Ignora linhas de metadados do Impacket (começam com [*], Impacket, etc.)
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "Impacket") ||
			strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		hash, err := ParseOutputLine(line)
		if err != nil {
			continue
		}

		hashes = append(hashes, *hash)
	}

	return hashes
}

// ParseOutputLine parseia uma única linha no formato "username:RID:LMHash:NTLMHash:::".
// Retorna o hash estruturado ou erro se o formato não for reconhecido.
func ParseOutputLine(line string) (*NTLMHash, error) {
	// Formato esperado: username:RID:LMHash:NTLMHash:::
	// Exemplo: Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("formato inválido: poucos campos")
	}

	rid, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("RID inválido: %s", parts[1])
	}

	ntlmHash := parts[3]
	// Um hash NTLM válido tem exatamente 32 caracteres hexadecimais
	if len(ntlmHash) != 32 {
		return nil, fmt.Errorf("NTLM hash inválido (len=%d)", len(ntlmHash))
	}

	return &NTLMHash{
		Username: parts[0],
		RID:      rid,
		LMHash:   parts[2],
		NTLMHash: ntlmHash,
	}, nil
}

// SaveHashFile salva apenas os hashes NTLM em um arquivo, um por linha.
// Este é o formato aceito pelo Hashcat com -m 1000.
func SaveHashFile(hashes []NTLMHash, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("erro ao criar arquivo: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, h := range hashes {
		// Pula hashes de senhas vazias — não faz sentido crackear
		if h.NTLMHash == EmptyNTLMHash {
			continue
		}
		fmt.Fprintln(w, h.NTLMHash)
	}
	return w.Flush()
}

// SaveFullDump salva o dump completo com usernames para referência humana.
// Formato: username:RID:LMHash:NTLMHash:::
func SaveFullDump(hashes []NTLMHash, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("erro ao criar arquivo: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, h := range hashes {
		fmt.Fprintf(w, "%s:%d:%s:%s:::\n", h.Username, h.RID, h.LMHash, h.NTLMHash)
	}
	return w.Flush()
}

// LoadHashFile carrega hashes NTLM de um arquivo existente (1 hash por linha ou formato user:rid:lm:ntlm:::).
// Aceita ambos os formatos para flexibilidade.
func LoadHashFile(filePath string) ([]NTLMHash, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("erro ao abrir arquivo: %w", err)
	}
	defer f.Close()

	var hashes []NTLMHash
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Tenta formato completo (user:rid:lm:ntlm:::)
		if hash, err := ParseOutputLine(line); err == nil {
			hashes = append(hashes, *hash)
			continue
		}

		// Tenta formato hash puro (32 hex chars)
		if len(line) == 32 {
			hashes = append(hashes, NTLMHash{
				Username: "desconhecido",
				NTLMHash: line,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("erro ao ler arquivo: %w", err)
	}

	return hashes, nil
}
