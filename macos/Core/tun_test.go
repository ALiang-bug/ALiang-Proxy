package main
import("encoding/json";"testing";"github.com/sagernet/sing-box/option";sj "github.com/sagernet/sing/common/json")
func TestTUNConfigurationBoundary(t *testing.T){
 c:=safeConfig();c["route"].(map[string]any)["auto_detect_interface"]=true;c["route"].(map[string]any)["default_domain_resolver"]="node-bootstrap";c["dns"]=bootstrapOptions("223.5.5.5","dns.alidns.com")
 raw,_:=json.Marshal(c);encoded,e:=tunConfiguration(raw);if e!=nil{t.Fatal(e)}
 // Parse without starting: this test must never create a TUN or alter routes.
 opts,e:=sj.UnmarshalExtendedContext[option.Options](desktopContext(),encoded);if e!=nil{t.Fatal("generated options invalid:",e)};if len(opts.Inbounds)!=1||opts.Inbounds[0].Type!="tun"{t.Fatal("missing TUN")}
 var result map[string]any;json.Unmarshal(encoded,&result);dns:=result["dns"].(map[string]any);if dns["final"]!="tun-business-dns"{t.Fatal("business DNS not isolated")}
 if validateDesktop(encoded)==nil{t.Fatal("normal mode admitted privileged config")}
 delete(c,"dns");raw,_=json.Marshal(c);if _,e=tunConfiguration(raw);e==nil{t.Fatal("missing DNS accepted")}
 c=safeConfig();c["dns"]=bootstrapOptions("223.5.5.5","dns.alidns.com");c["route"].(map[string]any)["default_domain_resolver"]="node-bootstrap";raw,_=json.Marshal(c);if _,e=tunConfiguration(raw);e==nil{t.Fatal("unbound TUN accepted")}
}
