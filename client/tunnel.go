package main

import (
	"net"
	"strings"
	"sync"
)

type tunnel struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     string `json:"port"`
	P12Path  string `json:"p12_path"`
	BindCIDR string `json:"bind_cidr"` // e.g. "127.0.0.1/32" or "192.168.0.0/24"
	Password string `json:"-"`

	status       string
	limitInKiB   int // 0 = unlimited
	limitOutKiB  int
	usedInBytes  int64
	usedOutBytes int64
	mu           sync.Mutex
	stopped      bool
	done         chan struct{}
	listener     net.Listener
}

func (t *tunnel) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	t.stopped = true
	close(t.done)
	if t.listener != nil {
		t.listener.Close()
	}
	t.status = "detenido"
}

func (t *tunnel) isActive() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.stopped
}

func (t *tunnel) setStatus(s string) {
	t.mu.Lock()
	t.status = s
	t.mu.Unlock()
}

func (t *tunnel) bindAddr() string {
	cidr := t.BindCIDR
	if cidr == "" {
		cidr = "127.0.0.1/32"
	}
	// Extract IP from CIDR for listen address
	ip := cidr
	if idx := strings.Index(cidr, "/"); idx >= 0 {
		ip = cidr[:idx]
	}
	return ip + ":" + t.Port
}

func (t *tunnel) setBandwidth(limitIn, limitOut int, usedIn, usedOut int64) {
	t.mu.Lock()
	t.limitInKiB = limitIn
	t.limitOutKiB = limitOut
	t.usedInBytes = usedIn
	t.usedOutBytes = usedOut
	t.mu.Unlock()
	tunnelsMu.Lock()
	saveConfig(allTunnels)
	tunnelsMu.Unlock()
}

func (t *tunnel) addBytes(upload, download int64) {
	t.mu.Lock()
	t.usedInBytes += upload
	t.usedOutBytes += download
	t.mu.Unlock()
}
