package main

import (
 "encoding/json"
 "errors"
)

// Privileged mode accepts the SAME unprivileged input boundary. All TUN
// addresses, routes and DNS actions are constructed here, never by imported YAML.
func tunConfiguration(data []byte) ([]byte,error) {
 if validateDesktop(data)!=nil{return nil,errors.New("unsafe_tun_configuration")}
 var config map[string]any
 if json.Unmarshal(data,&config)!=nil{return nil,errors.New("invalid_tun_configuration")}
 route:=config["route"].(map[string]any)
 if route["auto_detect_interface"]!=true{return nil,errors.New("tun_requires_interface_detection")}
 dns,ok:=config["dns"].(map[string]any)
 if !ok{return nil,errors.New("tun_requires_independent_dns")}
 // Keep bootstrap resolution independent of the proxy to avoid startup loops.
 servers:=dns["servers"].([]any)
 bootstrap:=servers[0].(map[string]any)
 business:=map[string]any{}
 for key,value:=range bootstrap{business[key]=value}
 business["tag"]="tun-business-dns"
 business["detour"]=route["final"]
 dns["servers"]=append(servers,business)
 dns["final"]="tun-business-dns"
 route["rules"]=[]any{map[string]any{"port":53,"action":"hijack-dns"}}
 config["inbounds"]=[]any{map[string]any{
  "type":"tun","tag":"privateproxy-tun","address":[]string{"172.29.255.1/30","fdfe:29:255::1/126"},
  "mtu":1400,"stack":"system","auto_route":true,"dns_mode":"hijack",
 }}
 return json.Marshal(config)
}
