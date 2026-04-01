package main

import (
	"net"
	"sync"
)

type tunnel struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     string `json:"port"`
	P12Path  string `json:"p12_path"`
	Password string `json:"-"`

	status        string
	remainingUses int // -1 = unlimited, 0+ = remaining
	mu            sync.Mutex
	stopped       bool
	done          chan struct{}
	listener      net.Listener
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

func (t *tunnel) setUses(n int) {
	t.mu.Lock()
	t.remainingUses = n
	t.mu.Unlock()
	tunnelsMu.Lock()
	saveConfig(allTunnels)
	tunnelsMu.Unlock()
}

func (t *tunnel) getUses() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remainingUses
}
