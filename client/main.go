package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// --- Tunnel state ---

type tunnel struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     string `json:"port"`
	P12Path  string `json:"p12_path"`
	Password string `json:"-"`

	status   string
	mu       sync.Mutex
	stopped  bool
	done     chan struct{}
	listener net.Listener
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

// --- Persistence ---

type savedConfig struct {
	Tunnels []savedTunnel `json:"tunnels"`
}

type savedTunnel struct {
	Name    string `json:"name"`
	Server  string `json:"server"`
	Port    string `json:"port"`
	P12Path string `json:"p12_path"`
}

func configPath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "bastion-client", "config.json")
}

func loadConfig() savedConfig {
	var cfg savedConfig
	data, err := os.ReadFile(configPath())
	if err != nil {
		return cfg
	}
	json.Unmarshal(data, &cfg)
	return cfg
}

func saveConfig(tunnels []*tunnel) {
	var cfg savedConfig
	for _, t := range tunnels {
		cfg.Tunnels = append(cfg.Tunnels, savedTunnel{
			Name: t.Name, Server: t.Server, Port: t.Port, P12Path: t.P12Path,
		})
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	p := configPath()
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, data, 0o644)
}

// --- Globals ---

var (
	allTunnels []*tunnel
	tunnelsMu  sync.Mutex
	listWidget *widget.List
)

func refreshList() {
	if listWidget != nil {
		listWidget.Refresh()
	}
}

func persistAndRefresh() {
	tunnelsMu.Lock()
	saveConfig(allTunnels)
	tunnelsMu.Unlock()
	refreshList()
}

// --- Main ---

func main() {
	a := app.NewWithID("com.bastion.client")
	w := a.NewWindow("Bastion Tunnel Client")
	w.Resize(fyne.NewSize(650, 420))

	listWidget = widget.NewList(
		func() int {
			tunnelsMu.Lock()
			defer tunnelsMu.Unlock()
			return len(allTunnels)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewIcon(theme.MediaStopIcon()),
				widget.NewLabel("name"),
				widget.NewLabel("→"),
				widget.NewLabel("server"),
				widget.NewLabel("status"),
				widget.NewButton("Detener", nil),
				widget.NewButton("×", nil),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			tunnelsMu.Lock()
			if id >= len(allTunnels) {
				tunnelsMu.Unlock()
				return
			}
			t := allTunnels[id]
			tunnelsMu.Unlock()

			box := obj.(*fyne.Container)
			icon := box.Objects[0].(*widget.Icon)
			nameLabel := box.Objects[1].(*widget.Label)
			arrow := box.Objects[2].(*widget.Label)
			serverLabel := box.Objects[3].(*widget.Label)
			statusLabel := box.Objects[4].(*widget.Label)
			stopBtn := box.Objects[5].(*widget.Button)
			removeBtn := box.Objects[6].(*widget.Button)

			nameLabel.SetText(fmt.Sprintf(":%s %s", t.Port, t.Name))
			arrow.SetText("→")
			serverLabel.SetText(t.Server)
			statusLabel.SetText(t.status)

			if t.isActive() {
				icon.SetResource(theme.MediaPlayIcon())
				statusLabel.Importance = widget.SuccessImportance
				stopBtn.SetText("Detener")
				stopBtn.Importance = widget.DangerImportance
				stopBtn.OnTapped = func() {
					t.stop()
					refreshList()
				}
			} else {
				icon.SetResource(theme.MediaStopIcon())
				statusLabel.Importance = widget.LowImportance
				stopBtn.SetText("Iniciar")
				stopBtn.Importance = widget.SuccessImportance
				stopBtn.OnTapped = func() {
					showReconnectDialog(w, t)
				}
			}

			capturedID := id
			removeBtn.Importance = widget.DangerImportance
			removeBtn.OnTapped = func() {
				t.stop()
				tunnelsMu.Lock()
				if capturedID < len(allTunnels) {
					allTunnels = append(allTunnels[:capturedID], allTunnels[capturedID+1:]...)
				}
				tunnelsMu.Unlock()
				persistAndRefresh()
			}
		},
	)

	addBtn := widget.NewButton("Agregar .p12", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			p12Path := reader.URI().Path()
			reader.Close()
			showP12Dialog(w, reader.URI().Name(), p12Path)
		}, w)
	})

	w.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		for _, uri := range uris {
			showP12Dialog(w, uri.Name(), uri.Path())
		}
	})

	top := container.NewHBox(addBtn)
	content := container.NewBorder(top, nil, nil, nil, listWidget)
	w.SetContent(content)

	// Load saved tunnels
	cfg := loadConfig()
	for _, st := range cfg.Tunnels {
		allTunnels = append(allTunnels, &tunnel{
			Name: st.Name, Server: st.Server, Port: st.Port, P12Path: st.P12Path,
			status: "detenido", stopped: true, done: make(chan struct{}),
		})
	}
	refreshList()

	w.ShowAndRun()
}

func showP12Dialog(w fyne.Window, filename, p12Path string) {
	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("servidor:3001")
	serverEntry.SetText(getEnvOr("BASTION_HOST", "localhost:3001"))
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Contraseña del .p12")
	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("Puerto local (ej: 8080)")

	dialog.ShowForm("Túnel: "+filename, "Conectar", "Cancelar",
		[]*widget.FormItem{
			widget.NewFormItem("Servidor", serverEntry),
			widget.NewFormItem("Contraseña", passEntry),
			widget.NewFormItem("Puerto local", portEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			t := &tunnel{
				Name:     filename,
				Server:   serverEntry.Text,
				Port:     portEntry.Text,
				P12Path:  p12Path,
				Password: passEntry.Text,
				status:   "conectando...",
				done:     make(chan struct{}),
			}
			tunnelsMu.Lock()
			allTunnels = append(allTunnels, t)
			tunnelsMu.Unlock()
			persistAndRefresh()
			go connectTunnel(w, t)
		}, w)
}

func showReconnectDialog(w fyne.Window, t *tunnel) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Contraseña del .p12")

	dialog.ShowForm("Reconectar: "+t.Name, "Conectar", "Cancelar",
		[]*widget.FormItem{
			widget.NewFormItem("Contraseña", passEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			t.mu.Lock()
			t.stopped = false
			t.done = make(chan struct{})
			t.status = "conectando..."
			t.Password = passEntry.Text
			t.mu.Unlock()
			refreshList()
			go connectTunnel(w, t)
		}, w)
}

func connectTunnel(w fyne.Window, t *tunnel) {
	p12Data, err := os.ReadFile(t.P12Path)
	if err != nil {
		t.mu.Lock()
		t.status = "error: archivo no encontrado"
		t.stopped = true
		t.mu.Unlock()
		refreshList()
		return
	}

	privateKey, cert, caCerts, err := gopkcs12.DecodeChain(p12Data, t.Password)
	if err != nil {
		t.mu.Lock()
		t.status = "error: contraseña incorrecta"
		t.stopped = true
		t.mu.Unlock()
		refreshList()
		return
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
	}
	caPool := x509.NewCertPool()
	for _, ca := range caCerts {
		caPool.AddCert(ca)
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	}

	// Verify server
	tr := &http.Transport{TLSClientConfig: tlsConfig}
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := cl.Get(fmt.Sprintf("https://%s/", t.Server))
	if err != nil {
		t.mu.Lock()
		t.status = "error: servidor no alcanzable"
		t.stopped = true
		t.mu.Unlock()
		refreshList()
		return
	}
	resp.Body.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:"+t.Port)
	if err != nil {
		t.mu.Lock()
		t.status = "error: puerto ocupado"
		t.stopped = true
		t.mu.Unlock()
		refreshList()
		return
	}
	t.mu.Lock()
	t.listener = ln
	t.status = "activo"
	t.mu.Unlock()
	refreshList()

	for {
		select {
		case <-t.done:
			return
		default:
		}
		ln.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := ln.Accept()
		if err != nil {
			if t.isActive() {
				continue
			}
			return
		}
		go handleConn(conn, t.Server, tlsConfig)
	}
}

func handleConn(local net.Conn, server string, tlsConfig *tls.Config) {
	defer local.Close()

	remote, err := tls.Dial("tcp", server, tlsConfig)
	if err != nil {
		return
	}
	defer remote.Close()

	upgrade := fmt.Sprintf(
		"GET /v1/events HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: v1\r\n\r\n",
		server,
	)
	remote.Write([]byte(upgrade))

	br := bufio.NewReader(remote)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				writeWSFrame(remote, buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			data, err := readWSFrame(br)
			if err != nil {
				break
			}
			if len(data) > 0 {
				local.Write(data)
			}
		}
	}()

	wg.Wait()
}

func writeWSFrame(w io.Writer, data []byte) {
	l := len(data)
	var hdr []byte
	if l < 126 {
		hdr = []byte{0x82, byte(l)}
	} else if l < 65536 {
		hdr = []byte{0x82, 126, byte(l >> 8), byte(l)}
	} else {
		hdr = []byte{0x82, 127, 0, 0, 0, 0, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	}
	w.Write(append(hdr, data...))
}

func readWSFrame(r *bufio.Reader) ([]byte, error) {
	b0, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	b1, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if b0&0x0F == 8 {
		return nil, io.EOF
	}

	masked := b1&0x80 != 0
	length := uint64(b1 & 0x7F)
	if length == 126 {
		buf := make([]byte, 2)
		io.ReadFull(r, buf)
		length = uint64(buf[0])<<8 | uint64(buf[1])
	} else if length == 127 {
		buf := make([]byte, 8)
		io.ReadFull(r, buf)
		length = uint64(buf[0])<<56 | uint64(buf[1])<<48 | uint64(buf[2])<<40 | uint64(buf[3])<<32 |
			uint64(buf[4])<<24 | uint64(buf[5])<<16 | uint64(buf[6])<<8 | uint64(buf[7])
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		io.ReadFull(r, mask)
	}

	data := make([]byte, length)
	_, err = io.ReadFull(r, data)
	if err != nil {
		return nil, err
	}
	if masked {
		for i := range data {
			data[i] ^= mask[i%4]
		}
	}
	return data, nil
}

func getEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
