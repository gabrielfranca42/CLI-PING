package main

import "github.com/gabrifranca/cli_ping/cmd/cli"

func main() {
	app := cli.NewCLI()
	app.ParseAndRun()
}
