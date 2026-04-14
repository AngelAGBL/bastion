package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type savedConfig struct {
	Tunnels []savedTunnel `json:"tunnels"`
}

type savedTunnel struct {
	Name         string `json:"name"`
	Server       string `json:"server"`
	Port         string `json:"port"`
	Protocol     string `json:"protocol"`
	P12Path      string `json:"p12_path"`
	BindCIDR     string `json:"bind_cidr"`
	CertExpiry   string `json:"cert_expiry,omitempty"`
	LimitInKiB   int    `json:"limit_in_kib"`
	LimitOutKiB  int    `json:"limit_out_kib"`
	UsedInBytes  int64  `json:"used_in_bytes"`
	UsedOutBytes int64  `json:"used_out_bytes"`
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
		expStr := ""
		if !t.certExpiry.IsZero() {
			expStr = t.certExpiry.Format(time.RFC3339)
		}
		cfg.Tunnels = append(cfg.Tunnels, savedTunnel{
			Name: t.Name, Server: t.Server, Port: t.Port, Protocol: t.Protocol,
			P12Path: t.P12Path, BindCIDR: t.BindCIDR, CertExpiry: expStr,
			LimitInKiB:  t.limitInKiB, LimitOutKiB: t.limitOutKiB,
			UsedInBytes: t.usedInBytes, UsedOutBytes: t.usedOutBytes,
		})
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	p := configPath()
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, data, 0o644)
}
