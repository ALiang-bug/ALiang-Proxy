package main

import (
 "bufio"
 "bytes"
 "context"
 "crypto/rand"
 "crypto/rsa"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/json"
 "encoding/pem"
 "io"
 "math/big"
 "net"
 "os"
 "os/exec"
 "strings"
 "strconv"
 "testing"
 "time"

 box "github.com/sagernet/sing-box"
 "github.com/sagernet/sing-box/adapter/certificate"
 "github.com/sagernet/sing-box/adapter/endpoint"
 "github.com/sagernet/sing-box/adapter/inbound"
 "github.com/sagernet/sing-box/adapter/outbound"
 "github.com/sagernet/sing-box/adapter/service"
 "github.com/sagernet/sing-box/dns"
 "github.com/sagernet/sing-box/dns/transport/local"
 "github.com/sagernet/sing-box/protocol/trojan"
 "github.com/sagernet/sing-box/protocol/vless"
 "github.com/sagernet/sing-box/protocol/direct"
 "github.com/sagernet/sing-box/option"
 sj "github.com/sagernet/sing/common/json"
)
func freePort(t *testing.T) int { t.Helper(); l,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil {t.Fatal(e)};p:=l.Addr().(*net.TCPAddr).Port;l.Close();return p }
func TestDesktopMixedTrojan(t *testing.T) {
 binary:=os.Getenv("DESKTOP_CORE");if binary=="" {t.Fatal("DESKTOP_CORE required")}
 key,_:=rsa.GenerateKey(rand.Reader,2048)
 cert:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"localhost"},DNSNames:[]string{"localhost"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
 der,e:=x509.CreateCertificate(rand.Reader,cert,cert,&key.PublicKey,key);if e!=nil {t.Fatal(e)}
 certPEM:=string(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})); keyPEM:=string(pem.EncodeToMemory(&pem.Block{Type:"RSA PRIVATE KEY",Bytes:x509.MarshalPKCS1PrivateKey(key)}))
 serverPort:=freePort(t)
 config:=map[string]any{"log":map[string]any{"disabled":true},"inbounds":[]any{map[string]any{"type":"trojan","listen":"127.0.0.1","listen_port":serverPort,"users":[]any{map[string]any{"password":"local-test-only"}},"tls":map[string]any{"enabled":true,"certificate":[]string{certPEM},"key":[]string{keyPEM}}}},"outbounds":[]any{map[string]any{"type":"direct","tag":"echo-only"}},"route":map[string]any{"final":"echo-only"}}
 ctx:=testServerContext();raw,_:=json.Marshal(config);options,e:=sj.UnmarshalExtendedContext[option.Options](ctx,raw);if e!=nil {t.Fatal(e)}
 server,e:=box.New(box.Options{Context:ctx,Options:options});if e!=nil {t.Fatal(e)};defer server.Close();if e=server.Start();e!=nil {t.Fatal(e)}
 echo,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil {t.Fatal(e)};defer echo.Close()
 go func(){for {c,e:=echo.Accept();if e!=nil{return};go func(){defer c.Close();io.Copy(c,c)}()}}()
 for _,protocol:=range []string{"http","socks5","wrong-password","wrong-hostname","wrong-ca"} {t.Run(protocol,func(t *testing.T){
  port:=freePort(t)
  client:=map[string]any{"inbounds":[]any{map[string]any{"type":"mixed","listen":"127.0.0.1","listen_port":port}},"outbounds":[]any{map[string]any{"type":"trojan","tag":"proxy","server":"127.0.0.1","server_port":serverPort,"password":"local-test-only","tls":map[string]any{"enabled":true,"server_name":"localhost","certificate":[]string{certPEM}}}},"route":map[string]any{"final":"proxy"}}
  if protocol=="wrong-password" {client["outbounds"].([]any)[0].(map[string]any)["password"]="rejected-password"}
  if protocol=="wrong-ca" {delete(client["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any),"certificate")}
  if protocol=="wrong-hostname" {client["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["server_name"]="mismatch.invalid"}
  raw,_:=json.Marshal(client);cmd:=exec.Command(binary,"run");cmd.Stdin=bytes.NewReader(raw);stdout,e:=cmd.StdoutPipe();if e!=nil{t.Fatal(e)};if e=cmd.Start();e!=nil{t.Fatal(e)};defer func(){cmd.Process.Signal(os.Interrupt);cmd.Wait()}()
  ready:=make(chan string,1);go func(){line,_:=bufio.NewReader(stdout).ReadString('\n');ready<-line}()
  select {case line:=<-ready:if line!="ready\n"{t.Fatal("not ready")};case <-time.After(10*time.Second):t.Fatal("startup timeout")}
  c,e:=net.DialTimeout("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)),time.Second);if e!=nil{t.Fatal(e)};defer c.Close();c.SetDeadline(time.Now().Add(5*time.Second));r:=bufio.NewReader(c)
  if protocol!="socks5" {io.WriteString(c,"CONNECT "+echo.Addr().String()+" HTTP/1.1\r\nHost: "+echo.Addr().String()+"\r\n\r\n");line,_:=r.ReadString('\n');if !strings.Contains(line,"200"){t.Fatalf("CONNECT rejected: %q",line)};for {line,e:=r.ReadString('\n');if e!=nil{t.Fatal(e)};if line=="\r\n"{break}}} else {
   c.Write([]byte{5,1,0});reply:=make([]byte,2);io.ReadFull(r,reply);if !bytes.Equal(reply,[]byte{5,0}){t.Fatal("SOCKS negotiation")}
   target:=echo.Addr().(*net.TCPAddr);c.Write([]byte{5,1,0,1,127,0,0,1,byte(target.Port>>8),byte(target.Port)})
   response:=make([]byte,10);if _,e=io.ReadFull(r,response);e!=nil||response[1]!=0{t.Fatal("SOCKS connect failed")}
  }
  payload:=[]byte("desktop-trojan-roundtrip");c.Write(payload);reply:=make([]byte,len(payload));n,e:=io.ReadFull(r,reply)
  if strings.HasPrefix(protocol,"wrong-"){
   if n!=0||e==nil{t.Fatal("invalid authentication delivered application data")}
   if timeout,ok:=e.(net.Error);ok&&timeout.Timeout(){t.Fatal("authentication rejection did not close connection")}
  }else if e!=nil||!bytes.Equal(reply,payload){t.Fatal("proxy roundtrip failed",e)}
 })}
}

func testServerContext() context.Context {
 in:=inbound.NewRegistry();trojan.RegisterInbound(in);vless.RegisterInbound(in)
 out:=outbound.NewRegistry();direct.RegisterOutbound(out)
 resolvers:=dns.NewTransportRegistry();local.RegisterTransport(resolvers)
 return box.Context(context.Background(),in,out,endpoint.NewRegistry(),resolvers,service.NewRegistry(),certificate.NewRegistry())
}
