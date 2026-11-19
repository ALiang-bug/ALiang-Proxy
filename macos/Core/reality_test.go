package main
import (
 "bufio"
 "bytes"
 "crypto/ecdh"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "encoding/base64"
 "encoding/json"
 "io"
 "math/big"
 "net"
 "os"
 "os/exec"
 "strconv"
 "strings"
 "sync"
 "testing"
 "time"
 box "github.com/sagernet/sing-box"
 "github.com/sagernet/sing-box/option"
 sj "github.com/sagernet/sing/common/json"
)
func TestDesktopVlessRealityVisionTCPUDP(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer handshake.Close()
	var open sync.Map
	defer func() { open.Range(func(key, value any) bool { key.(net.Conn).Close(); return true }) }()
	go func() {
		for {
			conn, err := handshake.Accept()
			if err != nil {
				return
			}
			open.Store(conn, true)
			go func() { defer conn.Close(); defer open.Delete(conn); io.Copy(io.Discard, conn) }()
		}
	}()
	echoTCP, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoTCP.Close()
	echoPort := echoTCP.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := echoTCP.Accept()
			if err != nil {
				return
			}
			open.Store(conn, true)
			go func() { defer conn.Close(); defer open.Delete(conn); io.Copy(conn, conn) }()
		}
	}()
	echoUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: echoPort})
	if err != nil {
		t.Fatal(err)
	}
	defer echoUDP.Close()
	go func() {
		payload := make([]byte, 65535)
		for {
			n, addr, err := echoUDP.ReadFromUDP(payload)
			if err != nil {
				return
			}
			echoUDP.WriteToUDP(payload[:n], addr)
		}
	}()
	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverPort := reserved.Addr().(*net.TCPAddr).Port
	reserved.Close()
	realityKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const user = "df10688e-614b-4dd0-876a-a106b726532e"
	serverConfig := map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "vless", "tag": "test-in", "listen": "127.0.0.1", "listen_port": serverPort, "users": []any{map[string]any{"uuid": user, "flow": "xtls-rprx-vision"}}, "tls": map[string]any{"enabled": true, "server_name": "localhost", "reality": map[string]any{"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(realityKey.Bytes()), "short_id": []string{"0123456789abcdef"}, "handshake": map[string]any{"server": "127.0.0.1", "server_port": handshake.Addr().(*net.TCPAddr).Port}}}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "echo"}},
		"route":     map[string]any{"final": "echo", "rules": []any{map[string]any{"inbound": []string{"test-in"}, "action": "route", "outbound": "echo", "override_address": "127.0.0.1", "override_port": echoPort}}},
	}
	raw, err := json.Marshal(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testServerContext()
	opts, err := sj.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	server, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	clientConfig := map[string]any{
		"inbounds":  []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": freePort(t)}},
		"outbounds": []any{map[string]any{"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort, "uuid": user, "flow": "xtls-rprx-vision", "tls": map[string]any{"enabled": true, "server_name": "localhost", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "reality": map[string]any{"enabled": true, "public_key": base64.RawURLEncoding.EncodeToString(realityKey.PublicKey().Bytes()), "short_id": "0123456789abcdef"}}}},
		"route":     map[string]any{"final": "proxy"},
	}
	exerciseDesktop(t, clientConfig, false)
	clientTLS := clientConfig["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)
	t.Run("RandomFingerprint", func(t *testing.T) {
		clientTLS["utls"].(map[string]any)["fingerprint"] = "random"
		defer func() { clientTLS["utls"].(map[string]any)["fingerprint"] = "chrome" }()
		exerciseDesktop(t, clientConfig, false)
	})
	t.Run("RejectWrongRealityKey", func(t *testing.T) {
		wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		reality := clientTLS["reality"].(map[string]any)
		reality["public_key"] = base64.RawURLEncoding.EncodeToString(wrongKey.PublicKey().Bytes())
		defer func() { reality["public_key"] = base64.RawURLEncoding.EncodeToString(realityKey.PublicKey().Bytes()) }()
		exerciseDesktop(t, clientConfig, true)
	})
	t.Run("RejectWrongVlessUUID", func(t *testing.T) {
		outbound := clientConfig["outbounds"].([]any)[0].(map[string]any)
		outbound["uuid"] = "af10688e-614b-4dd0-876a-a106b726532e"
		defer func() { outbound["uuid"] = user }()
		exerciseDesktop(t, clientConfig, true)
	})
}

func exerciseDesktop(t *testing.T,config map[string]any,reject bool){
 t.Helper()
 port:=freePort(t);config["inbounds"].([]any)[0].(map[string]any)["listen_port"]=port
 raw,_:=json.Marshal(config);cmd:=exec.Command(os.Getenv("DESKTOP_CORE"),"run");cmd.Stdin=bytes.NewReader(raw)
 stdout,e:=cmd.StdoutPipe();if e!=nil{t.Fatal(e)};if e=cmd.Start();e!=nil{t.Fatal(e)}
 defer func(){cmd.Process.Signal(os.Interrupt);cmd.Wait()}()
 ready:=make(chan string,1);go func(){line,_:=bufio.NewReader(stdout).ReadString('\n');ready<-line}()
 select{case line:=<-ready:if line!="ready\n"{t.Fatal("not ready")};case <-time.After(10*time.Second):t.Fatal("startup timeout")}
 c,e:=net.DialTimeout("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)),time.Second);if e!=nil{t.Fatal(e)};defer c.Close();c.SetDeadline(time.Now().Add(8*time.Second))
 io.WriteString(c,"CONNECT 198.51.100.7:443 HTTP/1.1\r\nHost: 198.51.100.7:443\r\n\r\n")
 r:=bufio.NewReader(c);line,e:=r.ReadString('\n');if e!=nil||!strings.Contains(line,"200"){t.Fatal("CONNECT failed")}
 for{line,e:=r.ReadString('\n');if e!=nil{t.Fatal(e)};if line=="\r\n"{break}}
 payload:=[]byte("desktop-reality-vision-roundtrip");c.Write(payload);reply:=make([]byte,len(payload));n,e:=io.ReadFull(r,reply)
 if reject{if n!=0||e==nil{t.Fatal("invalid Reality/VLESS credentials delivered data")};return}
 if e!=nil||!bytes.Equal(reply,payload){t.Fatal("Reality Vision TCP failed",e)}
 control,e:=net.Dial("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)));if e!=nil{t.Fatal(e)};defer control.Close();control.SetDeadline(time.Now().Add(8*time.Second))
 control.Write([]byte{5,1,0});header:=make([]byte,2);if _,e=io.ReadFull(control,header);e!=nil||!bytes.Equal(header,[]byte{5,0}){t.Fatal("SOCKS greeting")}
 control.Write([]byte{5,3,0,1,0,0,0,0,0,0});association:=make([]byte,10);if _,e=io.ReadFull(control,association);e!=nil||association[1]!=0||association[3]!=1{t.Fatal("SOCKS UDP associate",e)}
 relayPort:=int(association[8])<<8|int(association[9]);udp,e:=net.DialUDP("udp",nil,&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:relayPort});if e!=nil{t.Fatal(e)};defer udp.Close();udp.SetDeadline(time.Now().Add(8*time.Second))
 packet:=append([]byte{0,0,0,1,198,51,100,7,1,187},payload...);udp.Write(packet);buffer:=make([]byte,2048);n,e=udp.Read(buffer)
 if e!=nil||n<10||!bytes.Equal(buffer[10:n],payload){t.Fatal("Reality Vision UDP failed",e)}
}
