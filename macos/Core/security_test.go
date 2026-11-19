package main
import("encoding/json";"testing")
func safeConfig() map[string]any{return map[string]any{
 "inbounds":[]any{map[string]any{"type":"mixed","listen":"127.0.0.1","listen_port":17890}},
 "outbounds":[]any{map[string]any{"type":"trojan","tag":"proxy","server":"127.0.0.1","server_port":443,"password":"test-secret","tls":map[string]any{"enabled":true,"server_name":"localhost"}}},
 "route":map[string]any{"final":"proxy"},
}}
func TestDesktopSecurityGate(t *testing.T){
 mutations:=map[string]func(map[string]any){
 "LAN listener":func(c map[string]any){c["inbounds"].([]any)[0].(map[string]any)["listen"]="0.0.0.0"},
 "privileged port":func(c map[string]any){c["inbounds"].([]any)[0].(map[string]any)["listen_port"]=80},
 "automatic system change":func(c map[string]any){c["inbounds"].([]any)[0].(map[string]any)["set_system_proxy"]=true},
 "controller":func(c map[string]any){c["experimental"]=map[string]any{"clash_api":map[string]any{"external_controller":"0.0.0.0:9090"}}},
 "TLS bypass":func(c map[string]any){c["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["insecure"]=true},
 "file access":func(c map[string]any){c["outbounds"].([]any)[0].(map[string]any)["tls"].(map[string]any)["certificate_path"]="/etc/passwd"},
 "direct fallback":func(c map[string]any){c["outbounds"].([]any)[0].(map[string]any)["type"]="direct"},
 "untrusted route":func(c map[string]any){c["route"].(map[string]any)["rules"]=[]any{}},
 "missing exit":func(c map[string]any){c["route"].(map[string]any)["final"]="missing"},
 "cyclic selector":func(c map[string]any){c["outbounds"]=[]any{map[string]any{"type":"selector","tag":"proxy","outbounds":[]string{"proxy"},"default":"proxy"}}},
 }
 raw,_:=json.Marshal(safeConfig());if validateDesktop(raw)!=nil{t.Fatal("valid desktop config rejected")}
 for name,mutate:=range mutations{t.Run(name,func(t *testing.T){c:=safeConfig();mutate(c);raw,_:=json.Marshal(c);if validateDesktop(raw)==nil{t.Fatal("unsafe configuration admitted")}})}
}

func FuzzDesktopValidation(f *testing.F){
 raw,_:=json.Marshal(safeConfig());f.Add(raw);f.Add([]byte("null"));f.Add([]byte("{}"));f.Add([]byte("[]"))
 f.Fuzz(func(t *testing.T,input []byte){if len(input)>1<<20{t.Skip()};_ = validateDesktop(input)})
}

func TestBootstrapDNSBoundary(t *testing.T){
 for _,endpoint:=range [][2]string{{"223.5.5.5","dns.alidns.com"},{"1.1.1.1","cloudflare-dns.com"}}{
  c:=safeConfig();c["dns"]=bootstrapOptions(endpoint[0],endpoint[1]);c["route"].(map[string]any)["default_domain_resolver"]="node-bootstrap"
  raw,_:=json.Marshal(c);if validateDesktop(raw)!=nil{t.Fatal("valid TLS bootstrap rejected")}
 }
 for _,field:=range []string{"insecure","certificate_path","detour"}{t.Run(field,func(t *testing.T){
  c:=safeConfig();d:=bootstrapOptions("223.5.5.5","dns.alidns.com");c["dns"]=d;c["route"].(map[string]any)["default_domain_resolver"]="node-bootstrap"
  server:=d["servers"].([]any)[0].(map[string]any);server["tls"].(map[string]any)[field]=true
  raw,_:=json.Marshal(c);if validateDesktop(raw)==nil{t.Fatal("untrusted bootstrap accepted")}
 })}
 c:=safeConfig();c["dns"]=bootstrapOptions("127.0.0.1","untrusted.invalid");c["route"].(map[string]any)["default_domain_resolver"]="node-bootstrap";raw,_:=json.Marshal(c);if validateDesktop(raw)==nil{t.Fatal("arbitrary DNS accepted")}
}

// Only the client-controlled interface monitor flag may widen the route shape.
func TestDesktopInterfaceDetectionBoundary(t *testing.T) {
 for _,withDNS:=range []bool{false,true}{
  c:=safeConfig();route:=c["route"].(map[string]any);route["auto_detect_interface"]=true
  if withDNS{c["dns"]=bootstrapOptions("223.5.5.5","dns.alidns.com");route["default_domain_resolver"]="node-bootstrap"}
  raw,_:=json.Marshal(c);if validateDesktop(raw)!=nil{t.Fatal("interface detection rejected")}
  for _,value:=range []any{false,"en0",nil}{route["auto_detect_interface"]=value;raw,_=json.Marshal(c);if validateDesktop(raw)==nil{t.Fatal("invalid interface detection admitted")}}
  route["auto_detect_interface"]=true;route["default_interface"]="en0";raw,_=json.Marshal(c);if validateDesktop(raw)==nil{t.Fatal("imported interface override admitted")}
 }
}
