package main

import "github.com/gabrifranca/cli-ping/controller"

func main() {
	ctrl := controller.NewPingController()
	ctrl.ParseAndRun()
}
