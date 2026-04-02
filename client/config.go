package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type savedConfig struct {
	LastServer string        `json:"last_server,omitempty"`
	Tunnels    []savedTunnel `json:"tunnels"`
}

type savedTunnel struct {
	Name         string `json:"name"`
	Server       string `json:"server"`
	Port         string `json:"port"`
	P12Path      string `json:"p12_path"`
	BindCIDR     string `json:"bind_cidr"`
	LimitInKiB   int    `json:"limit_in_kib"`
	LimitOutKiB  int    `json:"limit_out_kib"`
	UsedInBytes  int64  `json:"used_in_bytes"`
	UsedOutBytes int64  `json:"used_out_bytes"`
}

var lastServer string

func configPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "bastion-client", "config.json")
}

func loadConfig() savedConfig {
	var cfg savedConfig
	data, _ := os.ReadFile(configPath())
	json.Unmarshal(data, &cfg)
	if cfg.LastServer != "" {
		lastServer = cfg.LastServer
	}
	return cfg
}

func saveConfig(tunnels []*tunnel) {
	var cfg savedConfig
	cfg.LastServer = lastServer
	for _, t := range tunnels {
		cfg.Tunnels = append(cfg.Tunnels, savedTunnel{
			Name: t.Name, Server: t.Server, Port: t.Port, P12Path: t.P12Path,
			BindCIDR:    t.BindCIDR,
			LimitInKiB:  t.limitInKiB, LimitOutKiB: t.limitOutKiB,
			UsedInBytes: t.usedInBytes, UsedOutBytes: t.usedOutBytes,
		})
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	p := configPath()
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, data, 0o644)
}
