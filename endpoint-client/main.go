package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func main() {
	p12Path := flag.String("p12", "", "Path to .p12 certificate file")
	localPort := flag.String("port", "", "Local port to expose (e.g. 3000)")
	localIP := flag.String("ip", "127.0.0.1", "Local IP to connect to")
	proto := flag.String("proto", "tcp", "Protocol: tcp or udp")
	password := flag.String("pass", "", "P12 password (empty for no password)")
	flag.Parse()

	if *p12Path == "" || *localPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: bastion-ep -p12 <file.p12> -port <local-port> [-ip <local-ip>] [-proto tcp|udp] [-pass <password>]\n")
		os.Exit(1)
	}

	p12Data, err := os.ReadFile(*p12Path)
	if err != nil {
		fatal("cannot read p12: %v", err)
	}

	privateKey, cert, caCerts, err := gopkcs12.DecodeChain(p12Data, *password)
	if err != nil {
		fatal("cannot decode p12: %v", err)
	}

	// Extract server address from CN
	server := cert.Subject.CommonName
	if server == "" {
		fatal("p12 certificate has no CN (server address)")
	}
	if !strings.Contains(server, ":") {
		server += ":443"
	}

	tlsCert := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: privateKey}
	caPool := x509.NewCertPool()
	for _, ca := range caCerts {
		caPool.AddCert(ca)
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true,
	}

	info("connecting to %s (exposing local %s:%s/%s)", server, *localIP, *localPort, *proto)

	for {
		err := runSession(server, *localIP, *localPort, *proto, tlsConfig)
		if err != nil {
			info("session ended: %v — reconnecting in 5s", err)
		} else {
			info("session ended — reconnecting in 5s")
		}
		time.Sleep(5 * time.Second)
	}
}

func runSession(server, localIP, localPort, proto string, tlsConfig *tls.Config) error {
	remote, err := tls.Dial("tcp", server, tlsConfig)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer remote.Close()

	// WebSocket upgrade to /ep
	upgrade := fmt.Sprintf(
		"GET /ep HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Local-Port: %s\r\n\r\n",
		server, localPort,
	)
	if _, err := remote.Write([]byte(upgrade)); err != nil {
		return fmt.Errorf("write upgrade: %w", err)
	}

	br := bufio.NewReader(remote)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != 101 {
		return fmt.Errorf("server rejected: %d", resp.StatusCode)
	}

	info("connected — waiting for tunnel traffic")

	// Map of channelId → local TCP connection
	channels := &sync.Map{}

	// Read frames from server: [4-byte channelId][payload]
	for {
		frame, err := readWSFrame(br)
		if err != nil {
			return fmt.Errorf("read frame: %w", err)
		}
		if len(frame) < 4 {
			continue
		}

		rawId := binary.BigEndian.Uint32(frame[:4])
		payload := frame[4:]

		// High bit set = channel close
		if rawId&0x80000000 != 0 {
			channelId := rawId & 0x7FFFFFFF
			if v, ok := channels.Load(channelId); ok {
				v.(net.Conn).Close()
				channels.Delete(channelId)
			}
			continue
		}

		channelId := rawId

		// Get or create local connection for this channel
		var conn net.Conn
		if v, ok := channels.Load(channelId); ok {
			conn = v.(net.Conn)
		} else {
			// New channel — open local connection
			localAddr := localIP + ":" + localPort
			conn, err = net.DialTimeout(proto, localAddr, 5*time.Second)
			if err != nil {
				info("channel %d: cannot connect to %s %s: %v", channelId, proto, localAddr, err)
				// Send close back to server
				closeFrame := make([]byte, 4)
				binary.BigEndian.PutUint32(closeFrame, channelId|0x80000000)
				writeWSFrame(remote, closeFrame)
				continue
			}
			channels.Store(channelId, conn)
			info("channel %d: connected to %s %s", channelId, proto, localAddr)

			// Read from local → send to server with channelId prefix
			go func(ch uint32, c net.Conn) {
				defer func() {
					c.Close()
					channels.Delete(ch)
					closeFrame := make([]byte, 4)
					binary.BigEndian.PutUint32(closeFrame, ch|0x80000000)
					writeWSFrame(remote, closeFrame)
				}()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						framed := make([]byte, 4+n)
						binary.BigEndian.PutUint32(framed[:4], ch)
						copy(framed[4:], buf[:n])
						writeWSFrame(remote, framed)
					}
					if err != nil {
						return
					}
				}
			}(channelId, conn)
		}

		// Forward payload to local connection
		if len(payload) > 0 {
			conn.Write(payload)
		}
	}
}

// WebSocket framing (same as tunnel client)

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

func info(format string, args ...any) {
	fmt.Printf("[ep-client %s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: %s\n", fmt.Sprintf(format, args...))
	os.Exit(1)
}
