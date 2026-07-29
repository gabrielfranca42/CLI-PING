package sam

// NTLMHash representa um hash de credencial Windows extraído do arquivo SAM.
type NTLMHash struct {
	Username string // Nome do usuário Windows (ex: "Administrador")
	RID      int    // Relative Identifier (500 = Admin, 501 = Guest, 1001+ = usuários criados)
	LMHash   string // LM Hash (desabilitado no Windows moderno: "aad3b435b51404eeaad3b435b51404ee")
	NTLMHash string // NTLM Hash (MD4 da senha em UTF-16LE) — alvo do cracking com Hashcat -m 1000
}

// SAMDumpResult armazena o resultado completo de uma extração de hashes do SAM.
type SAMDumpResult struct {
	Hashes     []NTLMHash // Lista de todos os hashes extraídos
	HashFile   string     // Caminho do arquivo com hashes puros (1 por linha) para Hashcat
	DumpFile   string     // Caminho do dump completo (user:rid:lm:ntlm:::) para referência
	TotalUsers int        // Total de contas de usuário encontradas
}

// EmptyNTLMHash é o hash NTLM para uma senha vazia.
// Contas com esse hash não precisam ser crackeadas — a senha é literalmente vazia.
const EmptyNTLMHash = "31d6cfe0d16ae931b73c59d7e0c089c0"

// DisabledLMHash é o valor padrão do LM Hash quando está desabilitado (Windows Vista+).
const DisabledLMHash = "aad3b435b51404eeaad3b435b51404ee"
