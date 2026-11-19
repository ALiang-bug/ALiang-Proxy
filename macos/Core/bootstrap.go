package main

import "encoding/json"

// Optional node-address DNS. This is not a DNS listener and never changes the
// Mac's DNS settings. Fixed IP endpoints avoid a dependency on system Fake-IP.
func bootstrapOptions(ip, name string) map[string]any {
 return map[string]any{"servers":[]any{map[string]any{"type":"https","tag":"node-bootstrap","server":ip,"server_port":443,"path":"/dns-query","tls":map[string]any{"enabled":true,"server_name":name}}},"final":"node-bootstrap","strategy":"ipv4_only"}
}
func validBootstrap(raw json.RawMessage) bool {
 var value any
 if json.Unmarshal(raw,&value)!=nil{return false}
 canonical,_:=json.Marshal(value)
 for _,endpoint:=range [][2]string{{"223.5.5.5","dns.alidns.com"},{"1.1.1.1","cloudflare-dns.com"}} {
  allowed,_:=json.Marshal(bootstrapOptions(endpoint[0],endpoint[1]))
  if string(canonical)==string(allowed){return true}
 }
 return false
}
