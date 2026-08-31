package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"github.com/gabrifranca/cli_ping/cmd/cli"
)

func main() {
	// Auto-escalonamento de privilégios no Linux
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		fmt.Println("[*] Elevando privilégios para modo Promíscuo (sudo)...")
		
		args := append([]string{os.Args[0]}, os.Args[1:]...)
		cmd := exec.Command("sudo", args...)
		
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		
		err := cmd.Run()
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
