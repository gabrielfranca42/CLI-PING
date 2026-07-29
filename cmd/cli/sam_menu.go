package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/gabrifranca/cli_ping/internal/domain"
	"github.com/gabrifranca/cli_ping/internal/sam"
	"github.com/gabrifranca/cli_ping/internal/wifi"
	"github.com/gabrifranca/cli_ping/view"
)

// SAM EXTRACTOR - Offline Dump & Hashcat NTLM Cracking
// ═══════════════════════════════════════════════════════════════════════════

func (c *CLI) runSAMMenu(scanner *bufio.Scanner) {
	for {
		fmt.Printf("\n  %s%s--- SAM Extractor (Dump + Crack NTLM) ---%s\n", view.Bold, view.Red, view.Reset)
		fmt.Printf("  %s[!] ATENÇÃO: Requer acesso físico (Boot USB) ou credenciais de Admin.%s\n", view.Yellow, view.Reset)

		path, err := c.wifiService.FindHashcat()
		if err != nil {
			fmt.Printf("  %s[!] Hashcat: Não encontrado.%s\n", view.Red, view.Reset)
		} else {
			fmt.Printf("  %s[*] Hashcat: %s%s\n", view.Green, path, view.Reset)
		}

		submenu := `  %s[ 1 ]%s Guia de Extração (Como obter os arquivos SAM e SYSTEM)
  %s[ 2 ]%s Parsear SAM + SYSTEM → Extrair Hashes NTLM
  %s[ 3 ]%s Crackear Hashes NTLM (Brute Force - GPU)
  %s[ 4 ]%s Crackear Hashes NTLM (Dicionário/Wordlist)
  %s[ 0 ]%s Voltar
`
		fmt.Printf(submenu,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Yellow, view.Reset,
			view.Red, view.Reset,
		)
		fmt.Printf("  %s%ssam >%s ", view.Bold, view.Red, view.Reset)

		if !scanner.Scan() {
			return
		}
		input := strings.TrimSpace(scanner.Text())

		switch input {
		case "0", "voltar":
			return
		case "1":
			fmt.Println(sam.GetOfflineGuide())
		case "2":
			c.runSAMParser(scanner)
		case "3":
			c.runSAMBruteForce(scanner)
		case "4":
			c.runSAMDictionary(scanner)
		default:
			c.printer.PrintError("Opção inválida.")
		}
	}
}

func (c *CLI) runSAMParser(scanner *bufio.Scanner) {
	fmt.Printf("\n  %s[*] Extração de Hashes NTLM%s\n", view.Cyan, view.Reset)
	
	toolName, toolPath, err := sam.FindParser()
	if err != nil {
		c.printer.PrintError(err.Error())
		fmt.Println(sam.GetToolInstallGuide())
		return
	}
	fmt.Printf("  %s[*] Ferramenta detectada: %s (%s)%s\n", view.Green, toolName, toolPath, view.Reset)

	fmt.Printf("  Caminho do arquivo SAM: ")
	if !scanner.Scan() { return }
	samPath := strings.TrimSpace(scanner.Text())
	
	fmt.Printf("  Caminho do arquivo SYSTEM: ")
	if !scanner.Scan() { return }
	systemPath := strings.TrimSpace(scanner.Text())

	fmt.Printf("\n  %s[*] Processando arquivos (isso pode levar alguns segundos)...%s\n", view.Cyan, view.Reset)
	
	// Salva no diretório atual (onde a CLI foi executada)
	currentDir, _ := os.Getwd()
	result, err := sam.ParseSAMFiles(samPath, systemPath, currentDir)
	
	if err != nil {
		c.printer.PrintError(err.Error())
		return
	}

	fmt.Printf("\n  %s[✓] Extração Concluída! Encontrados %d hashes.%s\n", view.Green, result.TotalUsers, view.Reset)
	
	// Exibe um resumo dos usuários encontrados
	for _, h := range result.Hashes {
		if h.NTLMHash == sam.EmptyNTLMHash {
			fmt.Printf("  - %s (RID: %d) -> %s[Senha Vazia]%s\n", h.Username, h.RID, view.Yellow, view.Reset)
		} else {
			fmt.Printf("  - %s (RID: %d) -> %s[Hash Extraído]%s\n", h.Username, h.RID, view.Green, view.Reset)
		}
	}

	fmt.Printf("\n  %s[*] Arquivo de Hashes NTLM salvo para o Hashcat:%s\n", view.Cyan, view.Reset)
	c.printCopyableFilePath(result.HashFile)
	
	if result.DumpFile != "" {
		fmt.Printf("  %s[*] Dump completo salvo em: %s%s\n", view.Dim, result.DumpFile, view.Reset)
	}

	fmt.Printf("\n  %s[*] Agora use as opções 3 ou 4 do menu SAM para crackear os hashes.%s\n", view.Cyan, view.Reset)
}

func (c *CLI) runSAMBruteForce(scanner *bufio.Scanner) {
	hashcatPath := c.wifiService.GetHashcatPath()
	if hashcatPath == "" {
		c.printer.PrintError("Hashcat não configurado. Volte ao menu WiFi (opção 6) -> Configurar caminho.")
		return
	}

	fmt.Printf("\n  %s[*] Passo 1: Arquivo de Hashes NTLM%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Cole o caminho do arquivo .txt gerado no passo 2:\n")
	fmt.Printf("  %s%sntlm_file >%s ", view.Bold, view.Red, view.Reset)
	
	if !scanner.Scan() { return }
	hashFile := strings.TrimSpace(scanner.Text())
	
	if _, err := os.Stat(hashFile); err != nil {
		c.printer.PrintError(fmt.Sprintf("Arquivo não encontrado: %s", hashFile))
		return
	}

	config := domain.HashcatConfig{
		BinaryPath:    hashcatPath,
		HandshakeFile: hashFile,
		AttackMode:    domain.HashcatBruteForce,
		HashMode:      1000, // Modo NTLM
	}

	fmt.Printf("\n  %s[*] Passo 2: Configurar Charset (Caracteres permitidos)%s\n", view.Cyan, view.Reset)
	fmt.Printf("  [ 1 ] Apenas Números (0-9)\n")
	fmt.Printf("  [ 2 ] Letras Minúsculas (a-z)\n")
	fmt.Printf("  [ 3 ] Letras (a-zA-Z) + Números (0-9)\n")
	fmt.Printf("  [ 4 ] Todos os caracteres (a-zA-Z0-9!@#$)\n")
	fmt.Printf("  %s%scharset >%s ", view.Bold, view.Red, view.Reset)
	
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
	fmt.Printf("  Mínimo (padrão 1, diferentemente de WiFi que exige 8): ")
	if !scanner.Scan() { return }
	minInput := strings.TrimSpace(scanner.Text())
	if minInput == "" { minInput = "1" }
	fmt.Sscanf(minInput, "%d", &config.MinLength)
	
	fmt.Printf("  Máximo (padrão 8): ")
	if !scanner.Scan() { return }
	maxInput := strings.TrimSpace(scanner.Text())
	if maxInput == "" { maxInput = "8" }
	fmt.Sscanf(maxInput, "%d", &config.MaxLength)
	
	if config.MinLength < 1 { config.MinLength = 1 }
	if config.MaxLength < config.MinLength { config.MaxLength = config.MinLength }

	fmt.Printf("\n  %s[*] Configuração concluída:%s\n", view.Green, view.Reset)
	fmt.Printf("  Hash Mode: 1000 (NTLM)\n")
	fmt.Printf("  Charset:   %s\n", wifi.GetCharsetDescription(config.Charset))
	fmt.Printf("  Tamanho:   %d a %d caracteres\n", config.MinLength, config.MaxLength)
	
	estimativa := wifi.EstimateCombinations(config.Charset, config.MinLength, config.MaxLength)
	fmt.Printf("  Combinações Estimadas: ~%d\n", estimativa)
	
	fmt.Printf("\n  %sIniciar ataque? (s/n):%s ", view.Bold, view.Reset)
	if !scanner.Scan() { return }
	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "s" {
		return
	}

	c.executeSAMHashcat(config)
}

func (c *CLI) runSAMDictionary(scanner *bufio.Scanner) {
	hashcatPath := c.wifiService.GetHashcatPath()
	if hashcatPath == "" {
		c.printer.PrintError("Hashcat não configurado. Volte ao menu WiFi (opção 6) -> Configurar caminho.")
		return
	}

	fmt.Printf("\n  %s[*] Passo 1: Arquivo de Hashes NTLM%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Cole o caminho do arquivo .txt gerado no passo 2:\n")
	fmt.Printf("  %s%sntlm_file >%s ", view.Bold, view.Red, view.Reset)
	
	if !scanner.Scan() { return }
	hashFile := strings.TrimSpace(scanner.Text())
	
	if _, err := os.Stat(hashFile); err != nil {
		c.printer.PrintError(fmt.Sprintf("Arquivo não encontrado: %s", hashFile))
		return
	}
	
	fmt.Printf("\n  %s[*] Passo 2: Arquivo de Wordlist%s\n", view.Cyan, view.Reset)
	fmt.Printf("  Digite o caminho para o arquivo .txt com as senhas (ex: rockyou.txt):\n")
	fmt.Printf("  %s%swordlist >%s ", view.Bold, view.Red, view.Reset)
	
	if !scanner.Scan() { return }
	wordlist := strings.TrimSpace(scanner.Text())
	
	if _, err := os.Stat(wordlist); err != nil {
		c.printer.PrintError(fmt.Sprintf("Arquivo não encontrado: %s", wordlist))
		return
	}
	
	config := domain.HashcatConfig{
		BinaryPath:    hashcatPath,
		HandshakeFile: hashFile,
		AttackMode:    domain.HashcatDictionary,
		WordlistPath:  wordlist,
		HashMode:      1000, // Modo NTLM
	}
	
	c.executeSAMHashcat(config)
}

func (c *CLI) executeSAMHashcat(config domain.HashcatConfig) {
	fmt.Printf("\n  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Red, view.Reset)
	fmt.Printf("  %s%s       SAM EXTRACTOR — HASHCAT NTLM CRACKING              %s\n", view.Bold, view.Red, view.Reset)
	fmt.Printf("  %s%s══════════════════════════════════════════════════════════%s\n", view.Bold, view.Red, view.Reset)
	c.executeHashcat(config)
}
