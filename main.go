package main

import "github.com/gabrifranca/cli_ping/controller"

func main() {
	ctrl := controller.NewPingController()
	ctrl.ParseAndRun()
}
