package main

// Explicitly opt-in diagnostics; ordinary builds never contact real nodes.
import (
 "context"
 "bytes"
 "crypto/tls"
 "encoding/json"
 "fmt"
 "os"
 "os/exec"
 "reflect"
 "regexp"
 "strings"
 "testing"
 "time"

 box "github.com/sagernet/sing-box"
 "github.com/sagernet/sing-box/option"
 M "github.com/sagernet/sing/common/metadata"
 sj "github.com/sagernet/sing/common/json"
)
func errorCodes(err error) []string {
 if err==nil{return nil}
 text:=strings.ToLower(err.Error()); codes:=[]string{reflect.TypeOf(err).String()}
 for _,candidate:=range []string{"no such host","timeout","connection refused","connection reset","unexpected eof","eof","certificate","reality","public key","tls","context deadline exceeded","default interface","invalid argument","dns","handshake","network is unreachable"}{if strings.Contains(text,candidate){codes=append(codes,candidate)}}
 return codes
}
func redactedError(err error, config map[string]any) string {
 if err==nil{return ""}
 text:=err.Error()
 var scrub func(any)
 scrub=func(value any){switch v:=value.(type){case map[string]any:for key,item:=range v{switch key{case "tag","server","server_name","uuid","password","public_key","short_id":if str,ok:=item.(string);ok&&str!=""{text=strings.ReplaceAll(text,str,"[redacted]")}};scrub(item)};case []any:for _,item:=range v{scrub(item)}}}
 scrub(config)
 for _,pattern:=range []string{`https?://[^\s]+`,`[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}`,`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`,`(?i)[a-z0-9][a-z0-9._-]*\.[a-z]{2,}`,`[0-9a-fA-F]{1,4}:[0-9a-fA-F:]{2,}`} {text=regexp.MustCompile(pattern).ReplaceAllString(text,"[redacted]")}
 if len(text)>512{text=text[:512]}
 return text
}
func TestOptInRealNodeProbe(t *testing.T){
 path:=os.Getenv("PRIVATEPROXY_REAL_PROFILE")
 if path==""{t.Skip("real-node probing requires explicit profile opt-in")}
 data,e:=os.ReadFile(path);if e!=nil||len(data)>1<<20{t.Fatal("profile unavailable")}
 command:=exec.Command(os.Getenv("DESKTOP_CORE"),"compile");command.Stdin=bytes.NewReader(data);compiled,e:=command.Output();if e!=nil{t.Fatal("configuration rejected")}
 var envelope struct{Envelope struct{CoreJSON string `json:"coreJSON"`} `json:"envelope"`}
 if json.Unmarshal(compiled,&envelope)!=nil{t.Fatal("invalid compiled envelope")}
 var raw map[string]any;if json.Unmarshal([]byte(envelope.Envelope.CoreJSON),&raw)!=nil{t.Fatal("invalid compiled core")}
 route:=raw["route"].(map[string]any);tags:=[]string{route["final"].(string)}
 for _,entry:=range raw["outbounds"].([]any){out:=entry.(map[string]any);if out["type"]=="trojan"{tags=append(tags,out["tag"].(string));break}}
 for i,tag:=range tags{
  raw["inbounds"]=[]any{};raw["dns"]=bootstrapOptions("223.5.5.5","dns.alidns.com");raw["route"]=map[string]any{"final":tag,"default_domain_resolver":"node-bootstrap"}
  encoded,_:=json.Marshal(raw);ctx,cancel:=context.WithTimeout(desktopContext(),20*time.Second)
  opts,e:=sj.UnmarshalExtendedContext[option.Options](ctx,encoded);if e!=nil{cancel();t.Fatal("option parse failed")}
  service,e:=box.New(box.Options{Context:ctx,Options:opts});if e!=nil{cancel();t.Fatal("initialization failed")}
  if e=service.Start();e!=nil{service.Close();cancel();t.Fatal("startup failed")}
  conn,e:=service.Outbound().Default().DialContext(ctx,"tcp",M.ParseSocksaddr("www.apple.com:443"))
  if e!=nil{fmt.Printf("redacted mode=%d phase=node_dial codes=%v\n",i,errorCodes(e));fmt.Printf("sanitized detail=%s\n",redactedError(e,raw))}else{
   conn.SetDeadline(time.Now().Add(15*time.Second));remote:=tls.Client(conn,&tls.Config{ServerName:"www.apple.com",MinVersion:tls.VersionTLS12})
   e=remote.HandshakeContext(ctx);fmt.Printf("redacted mode=%d phase=website_tls ok=%t codes=%v\n",i,e==nil,errorCodes(e));fmt.Printf("sanitized detail=%s\n",redactedError(e,raw));remote.Close()
  }
  service.Close();cancel()
 }
}
