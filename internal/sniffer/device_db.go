package sniffer

import (
	"encoding/json"
	"os"
)

const devicesFile = "known_devices.json"

type KnownDevice struct {
	OS       string `json:"os"`
	LastIP   string `json:"last_ip"`
	Hostname string `json:"hostname"`
}

func loadKnownDevices() map[string]KnownDevice {
	data, err := os.ReadFile(devicesFile)
	if err != nil {
		return make(map[string]KnownDevice)
	}
	var db map[string]KnownDevice
	if err := json.Unmarshal(data, &db); err != nil {
		return make(map[string]KnownDevice)
	}
	return db
}

func saveKnownDevices(db map[string]KnownDevice) {
	data, _ := json.MarshalIndent(db, "", "  ")
	_ = os.WriteFile(devicesFile, data, 0644)
}
