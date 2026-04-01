package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type savedConfig struct {
	Tunnels []savedTunnel `json:"tunnels"`
}

type savedTunnel struct {
	Name          string `json:"name"`
	Server        string `json:"server"`
	Port          string `json:"port"`
	P12Path       string `json:"p12_path"`
	RemainingUses int    `json:"remaining_uses"`
}

func configPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "bastion-client", "config.json")
}

func loadConfig() savedConfig {
	var cfg savedConfig
	data, _ := os.ReadFile(configPath())
	json.Unmarshal(data, &cfg)
	return cfg
}

func saveConfig(tunnels []*tunnel) {
	var cfg savedConfig
	for _, t := range tunnels {
		cfg.Tunnels = append(cfg.Tunnels, savedTunnel{
			Name: t.Name, Server: t.Server, Port: t.Port, P12Path: t.P12Path,
			RemainingUses: t.getUses(),
		})
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	p := configPath()
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, data, 0o644)
}
