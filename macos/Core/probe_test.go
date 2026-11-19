package main
import("context";"io";"net/http";"net/http/httptest";"strings";"testing";"time")
func TestProbeMeasurements(t *testing.T){
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){switch r.URL.Path{case "/ok":io.WriteString(w,"Success");case "/speed":io.CopyN(w,strings.NewReader(strings.Repeat("a",int(speedBytes))),speedBytes);case "/short":io.WriteString(w,"short");case "/redirect":http.Redirect(w,r,"/ok",302);default:w.WriteHeader(503)}}));defer server.Close()
 client:=server.Client();client.CheckRedirect=func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}
 for _,item:=range []struct{path string;speed,ok bool}{{"/ok",false,true},{"/speed",true,true},{"/short",true,false},{"/short",false,false},{"/redirect",false,false},{"/bad",false,false}}{
  result:=measureProbe(context.Background(),client,server.URL+item.path,item.speed);if result.OK!=item.ok{t.Fatalf("measurement mismatch %s",item.path)};if item.speed&&result.OK&&(result.Bytes!=speedBytes||result.MBps<=0){t.Fatal("invalid throughput")}
 }
 ctx,cancel:=context.WithCancel(context.Background());cancel();if measureProbe(ctx,client,server.URL+"/ok",false).OK{t.Fatal("cancel ignored")}
 client.Timeout=time.Second
}

func TestProbeRejectsUnsafeConfigurationBeforeNetworking(t *testing.T){
 for _,raw:=range []string{"{}","null",`{"inbounds":[{"type":"tun"}]}`,`{"experimental":{"clash_api":{}}}`} {if result:=runProbe([]byte(raw),false);result.OK||result.Error!="configuration_rejected"{t.Fatal("invalid probe config admitted")}}
}
