package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

type verifyResult struct {
	ok           bool
	limitInKiB   int
	limitOutKiB  int
	usedInBytes  int64
	usedOutBytes int64
	active       bool
	err          string
}

func callVerify(server string, tlsConfig *tls.Config) verifyResult {
	tr := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true}
	cl := &http.Client{Transport: tr}
	resp, err := cl.Get(fmt.Sprintf("https://%s/verify", server))
	if err != nil {
		return verifyResult{err: "certificado rechazado"}
	}
	resp.Body.Close()
	tr.CloseIdleConnections()
	if resp.StatusCode != 200 {
		return verifyResult{err: "certificado no registrado"}
	}
	var limitIn, limitOut int
	var usedIn, usedOut int64
	fmt.Sscanf(resp.Header.Get("X-Limit-In-KiB"), "%d", &limitIn)
	fmt.Sscanf(resp.Header.Get("X-Limit-Out-KiB"), "%d", &limitOut)
	fmt.Sscanf(resp.Header.Get("X-Used-In-Bytes"), "%d", &usedIn)
	fmt.Sscanf(resp.Header.Get("X-Used-Out-Bytes"), "%d", &usedOut)
	active := resp.Header.Get("X-Active") == "true"
	return verifyResult{ok: true, limitInKiB: limitIn, limitOutKiB: limitOut, usedInBytes: usedIn, usedOutBytes: usedOut, active: active}
}

func dialWS(server string, tlsConfig *tls.Config) (net.Conn, *bufio.Reader, *http.Response, error) {
	remote, err := tls.Dial("tcp", server, tlsConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("tls: %w", err)
	}
	upgrade := fmt.Sprintf(
		"GET /v1/events HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: v1\r\n\r\n",
		server,
	)
	if _, err := remote.Write([]byte(upgrade)); err != nil {
		remote.Close()
		return nil, nil, nil, fmt.Errorf("write: %w", err)
	}
	br := bufio.NewReader(remote)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		remote.Close()
		return nil, nil, nil, fmt.Errorf("server closed connection")
	}
	if resp.StatusCode != 101 {
		remote.Close()
		return nil, nil, resp, fmt.Errorf("rejected: %d", resp.StatusCode)
	}
	return remote, br, resp, nil
}

func failTunnel(t *tunnel, msg string) {
	t.mu.Lock()
	t.status = msg
	t.stopped = true
	t.mu.Unlock()
	if t.listener != nil {
		t.listener.Close()
	}
	refreshList()
}

func connectTunnel(w fyne.Window, t *tunnel) {
	p12Data, err := os.ReadFile(t.P12Path)
	if err != nil {
		failTunnel(t, "error: archivo no encontrado")
		return
	}
	privateKey, cert, caCerts, err := gopkcs12.DecodeChain(p12Data, t.Password)
	if err != nil {
		failTunnel(t, "error: contraseña incorrecta")
		return
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: privateKey}
	caPool := x509.NewCertPool()
	for _, ca := range caCerts {
		caPool.AddCert(ca)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}, InsecureSkipVerify: true}

	vr := callVerify(t.Server, tlsConfig)
	if !vr.ok {
		failTunnel(t, "error: "+vr.err)
		return
	}
	t.setBandwidth(vr.limitInKiB, vr.limitOutKiB, vr.usedInBytes, vr.usedOutBytes)
	if !vr.active {
		failTunnel(t, "error: endpoint no activo")
		return
	}

	ln, err := net.Listen("tcp", t.bindAddr())
	if err != nil {
		failTunnel(t, "error: puerto ocupado")
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
		go handleConn(conn, t, tlsConfig)
	}
}

func handleConn(local net.Conn, t *tunnel, tlsConfig *tls.Config) {
	defer local.Close()

	remote, br, resp, err := dialWS(t.Server, tlsConfig)
	if err != nil {
		if resp != nil {
			errMsg := resp.Header.Get("X-Error")
			if errMsg == "" {
				errMsg = fmt.Sprintf("rechazado (%d)", resp.StatusCode)
			}
			failTunnel(t, "error: "+errMsg)
		} else {
			failTunnel(t, "error: certificado rechazado")
		}
		return
	}
	defer remote.Close()

	// Ticker to refresh UI during long-lived connections
	refreshDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-refreshDone:
				return
			case <-ticker.C:
				refreshList()
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// local → remote (upload)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				writeWSFrame(remote, buf[:n])
				t.addBytes(int64(n), 0)
			}
			if err != nil {
				break
			}
		}
	}()

	// remote → local (download)
	go func() {
		defer wg.Done()
		for {
			data, err := readWSFrame(br)
			if err != nil {
				break
			}
			if len(data) > 0 {
				local.Write(data)
				t.addBytes(0, int64(len(data)))
			}
		}
	}()

	wg.Wait()
	close(refreshDone)

	// Corroborate with server after connection closes
	post := callVerify(t.Server, tlsConfig)
	if post.ok {
		t.setBandwidth(post.limitInKiB, post.limitOutKiB, post.usedInBytes, post.usedOutBytes)
	}
	refreshList()
}

// WebSocket framing

func writeWSFrame(w io.Writer, data []byte) {
	l := len(data)
	var maskKey [4]byte
	rand.Read(maskKey[:])
	var hdr []byte
	if l < 126 {
		hdr = []byte{0x82, 0x80 | byte(l)}
	} else if l < 65536 {
		hdr = []byte{0x82, 0x80 | 126, byte(l >> 8), byte(l)}
	} else {
		hdr = []byte{0x82, 0x80 | 127, 0, 0, 0, 0, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	}
	hdr = append(hdr, maskKey[:]...)
	masked := make([]byte, l)
	for i := 0; i < l; i++ {
		masked[i] = data[i] ^ maskKey[i%4]
	}
	w.Write(append(hdr, masked...))
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
