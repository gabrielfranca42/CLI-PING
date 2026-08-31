package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/gabrifranca/cli_ping/cmd/cli"
)

func main() {
	// No Linux, se não for root, reinicia o processo usando sudo para garantir permissões de captura de pacotes (CAP_NET_RAW).
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Println("[*] O programa necessita de privilégios de root para captura de pacotes (CAP_NET_RAW).")
		fmt.Println("[*] Tentando elevar privilégios com sudo...")

		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Erro ao obter o caminho do executável: %v\n", err)
			os.Exit(1)
		}

		cmd := exec.Command("sudo", append([]string{exe}, os.Args[1:]...)...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "Erro ao executar com sudo: %v\n", err)
			os.Exit(1)
		}
		return
	}

	app := cli.NewCLI()
	app.ParseAndRun()
}
