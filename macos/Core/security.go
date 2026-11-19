package main

import (
 "encoding/json"
 "errors"
)
// Desktop input is deliberately narrower than sing-box configuration. Imported
// YAML cannot add listeners, controllers, local files, or privileged TUN devices.
func validateDesktop(data []byte) error {
 reject:=func()error{return errors.New("unsafe_desktop_configuration")}
 var root map[string]json.RawMessage
 if json.Unmarshal(data,&root)!=nil{return reject()}
 for key:=range root {if key!="log"&&key!="inbounds"&&key!="outbounds"&&key!="route"&&key!="dns"{return reject()}}
 var ins []map[string]any
 if json.Unmarshal(root["inbounds"],&ins)!=nil||len(ins)!=1{return reject()}
 in:=ins[0]
 for key:=range in {switch key{case "type","tag","listen","listen_port","set_system_proxy":default:return reject()}}
 if in["type"]!="mixed"||in["listen"]!="127.0.0.1"{return reject()}
 port,ok:=in["listen_port"].(float64);if !ok||port<1025||port>65535||port!=float64(int(port)){return reject()}
 if v,ok:=in["set_system_proxy"];ok&&v!=false{return reject()}
 var route map[string]any
 if json.Unmarshal(root["route"],&route)!=nil{return reject()}
 routeFields:=len(route)
 if value,present:=route["auto_detect_interface"];present{if value!=true{return reject()};routeFields--}
 if raw,hasDNS:=root["dns"];hasDNS {
  if !validBootstrap(raw)||routeFields!=2||route["default_domain_resolver"]!="node-bootstrap"{return reject()}
 } else if routeFields!=1{return reject()}
 final,ok:=route["final"].(string);if !ok||final==""{return reject()}
 var outs []map[string]any
 if json.Unmarshal(root["outbounds"],&outs)!=nil||len(outs)==0||len(outs)>2176{return reject()}
 known:=map[string]bool{};groups:=map[string][]string{}
 for _,out:=range outs{
  tag,ok:=out["tag"].(string);if !ok||tag==""||known[tag]{return reject()};known[tag]=true
  kind,_:=out["type"].(string)
  allowed:=map[string]bool{"type":true,"tag":true}
  switch kind{
  case "vless","trojan":
   for _,k:=range []string{"server","server_port","tls","uuid","password","flow","network"}{allowed[k]=true}
   tls,ok:=out["tls"].(map[string]any);if !ok||tls["enabled"]!=true{return reject()}
   for k:=range tls{switch k{case "enabled","server_name","utls","reality","certificate":default:return reject()}}
   if utls,ok:=tls["utls"].(map[string]any);ok{for k:=range utls{if k!="enabled"&&k!="fingerprint"{return reject()}}}
   if reality,ok:=tls["reality"].(map[string]any);ok{for k:=range reality{if k!="enabled"&&k!="public_key"&&k!="short_id"{return reject()}}}
  case "selector":
   allowed["outbounds"]=true;allowed["default"]=true
   members,ok:=out["outbounds"].([]any);if !ok||len(members)==0{return reject()}
   found:=false;for _,m:=range members{s,ok:=m.(string);if !ok{return reject()};groups[tag]=append(groups[tag],s);if out["default"]==s{found=true}}
   if !found{return reject()}
  default:return reject()
  }
  for k:=range out{if !allowed[k]{return reject()}}
 }
 if !known[final]{return reject()}
 color:=map[string]int{}
 var visit func(string)bool
 visit=func(tag string)bool{if !known[tag]||color[tag]==1{return false};if color[tag]==2{return true};color[tag]=1;for _,m:=range groups[tag]{if !visit(m){return false}};color[tag]=2;return true}
 for tag:=range known{if !visit(tag){return reject()}}
 return nil
}
