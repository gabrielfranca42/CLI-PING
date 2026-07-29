package sam

// GetOfflineGuide retorna instruções detalhadas para extrair o SAM+SYSTEM
// de uma máquina Windows via boot USB com Linux.
// NÃO precisa desmontar o PC nem remover o Windows.
func GetOfflineGuide() string {
	return `
╔══════════════════════════════════════════════════════════════════════════╗
║          GUIA: EXTRAÇÃO DO SAM (SEM DESMONTAR O PC)                     ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  ⚠️  IMPORTANTE: Você NÃO precisa desmontar o computador, NÃO precisa    ║
║     remover o HD, e NÃO precisa desinstalar o Windows.                   ║
║     É só reiniciar de um pendrive. O Windows continua intacto.           ║
║                                                                          ║
║  ═══════════════════════════════════════════════════════════════════      ║
║  MÉTODO 1: BOOT USB COM LINUX (SEM ADMIN, SEM REDE)                     ║
║  ═══════════════════════════════════════════════════════════════════      ║
║                                                                          ║
║  O que acontece: Você liga o PC pelo pendrive. O Linux carrega na RAM.   ║
║  O Windows fica "desligado" e seus arquivos ficam livres para copiar.    ║
║  Depois é só reiniciar e o Windows volta normal, sem nenhuma alteração.  ║
║                                                                          ║
║  PASSO 1 — No SEU computador, crie um pendrive bootável:                 ║
║  ┌───────────────────────────────────────────────────────────────────┐   ║
║  │  1. Baixe a ISO do Kali Linux: https://www.kali.org/get-kali/    │   ║
║  │  2. Baixe o Rufus: https://rufus.ie/                             │   ║
║  │  3. Abra o Rufus → selecione o pendrive → selecione a ISO       │   ║
║  │  4. Clique em INICIAR e aguarde gravar                           │   ║
║  │                                                                   │   ║
║  │  💡 O pendrive precisa ter pelo menos 8GB                        │   ║
║  │  💡 Qualquer distro Linux serve (Ubuntu, Parrot, etc.)           │   ║
║  └───────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  PASSO 2 — Na máquina ALVO, dê boot pelo pendrive:                      ║
║  ┌───────────────────────────────────────────────────────────────────┐   ║
║  │  1. Espete o pendrive USB na máquina alvo                        │   ║
║  │  2. Reinicie (ou ligue) o computador                             │   ║
║  │  3. Pressione F12, F2, DEL ou ESC repetidamente durante o boot   │   ║
║  │     (depende da marca — a tecla aparece rápido na tela)          │   ║
║  │  4. No menu de boot, selecione o pendrive USB                    │   ║
║  │  5. Escolha "Live" ou "Try Kali without installing"              │   ║
║  │                                                                   │   ║
║  │  💡 Se não aparecer o menu: entre na BIOS e mude a ordem de     │   ║
║  │     boot para USB primeiro                                       │   ║
║  │  💡 Se tiver Secure Boot ativo, desabilite na BIOS               │   ║
║  └───────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  PASSO 3 — Dentro do Linux, monte a partição Windows:                    ║
║  ┌───────────────────────────────────────────────────────────────────┐   ║
║  │  Abra o Terminal e digite:                                       │   ║
║  │                                                                   │   ║
║  │  sudo fdisk -l                                                    │   ║
║  │  # Procure a partição NTFS grande (ex: /dev/sda2 ou /dev/nvme..) │   ║
║  │                                                                   │   ║
║  │  sudo mkdir /mnt/windows                                          │   ║
║  │  sudo mount -t ntfs-3g /dev/sda2 /mnt/windows                    │   ║
║  │  # Troque /dev/sda2 pela partição correta do seu caso            │   ║
║  │                                                                   │   ║
║  │  💡 Se der erro, tente: sudo mount -t ntfs-3g -o ro /dev/sda2   │   ║
║  │     /mnt/windows  (monta somente-leitura)                        │   ║
║  └───────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  PASSO 4 — Copie os arquivos SAM e SYSTEM:                               ║
║  ┌───────────────────────────────────────────────────────────────────┐   ║
║  │  # Os arquivos ficam em:                                          │   ║
║  │  ls /mnt/windows/Windows/System32/config/                         │   ║
║  │                                                                   │   ║
║  │  # Copie para o Desktop (ou outro pendrive):                      │   ║
║  │  cp /mnt/windows/Windows/System32/config/SAM ~/Desktop/           │   ║
║  │  cp /mnt/windows/Windows/System32/config/SYSTEM ~/Desktop/        │   ║
║  │                                                                   │   ║
║  │  💡 Os nomes podem estar em maiúscula ou minúscula               │   ║
║  │  💡 Copie os DOIS arquivos — ambos são necessários               │   ║
║  └───────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  PASSO 5 — Traga os arquivos para o seu PC:                              ║
║  ┌───────────────────────────────────────────────────────────────────┐   ║
║  │  • Copie os arquivos para um segundo pendrive, OU                 │   ║
║  │  • Se o Kali tem internet, envie por email/drive para você, OU    │   ║
║  │  • Se o boot foi no seu próprio PC, já estão no Desktop           │   ║
║  │                                                                   │   ║
║  │  Depois: reinicie a máquina, remova o pendrive.                   │   ║
║  │  O Windows liga normalmente, sem nenhuma alteração.               │   ║
║  └───────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  PASSO 6 — Use este programa para extrair e crackear:                    ║
║  ┌───────────────────────────────────────────────────────────────────┐   ║
║  │  Volte a este menu e use:                                         │   ║
║  │  → Opção 2: Extrair Hashes (informe os caminhos do SAM e SYSTEM) │   ║
║  │  → Opção 3 ou 4: Crackear com Hashcat (Brute Force ou Wordlist)  │   ║
║  └───────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  ═══════════════════════════════════════════════════════════════════      ║
║  MÉTODO 2: DIRETO NO WINDOWS (REQUER ADMIN)                             ║
║  ═══════════════════════════════════════════════════════════════════      ║
║                                                                          ║
║  Se você JÁ TEM acesso de administrador na máquina (ex: durante          ║
║  um pentest com credenciais obtidas), use este atalho mais rápido:       ║
║                                                                          ║
║  ┌───────────────────────────────────────────────────────────────────┐   ║
║  │  Abra CMD ou PowerShell COMO ADMINISTRADOR e execute:             │   ║
║  │                                                                   │   ║
║  │  reg save HKLM\SAM C:\Users\Public\sam /y                        │   ║
║  │  reg save HKLM\SYSTEM C:\Users\Public\system /y                  │   ║
║  │                                                                   │   ║
║  │  Depois copie os arquivos de C:\Users\Public\ para o seu PC.     │   ║
║  └───────────────────────────────────────────────────────────────────┘   ║
║                                                                          ║
║  ═══════════════════════════════════════════════════════════════════      ║
║  ⚠️  BITLOCKER: Se o disco estiver encriptado, o Método 1 não           ║
║     funciona sem a chave de recuperação do BitLocker.                    ║
║     Nesse caso, use o Método 2 (precisa de admin na máquina).           ║
║  ═══════════════════════════════════════════════════════════════════      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝`
}

// GetToolInstallGuide retorna instruções para instalar as ferramentas de parsing.
func GetToolInstallGuide() string {
	return `
  ┌───────────────────────────────────────────────────────────────────┐
  │  COMO INSTALAR UMA FERRAMENTA DE PARSING:                        │
  │                                                                   │
  │  Opção A — Impacket (RECOMENDADO):                                │
  │    pip install impacket                                           │
  │    # Depois use: impacket-secretsdump -sam SAM -system SYSTEM LOCAL│
  │                                                                   │
  │  Opção B — samdump2 (Linux apenas):                               │
  │    sudo apt install samdump2                                      │
  │    # Depois use: samdump2 SYSTEM SAM                              │
  │                                                                   │
  │  Opção C — secretsdump.exe standalone (Windows):                  │
  │    Baixe de: github.com/fortra/impacket/releases                  │
  │    Coloque no PATH ou na mesma pasta do Ajin                      │
  │                                                                   │
  │  Após instalar, volte e use a opção 2 deste menu.                 │
  └───────────────────────────────────────────────────────────────────┘`
}
