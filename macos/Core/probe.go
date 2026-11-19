package main

import (
 "context"
 "encoding/json"
 "errors"
 "io"
 "net"
 "net/http"
 "os"
 "os/signal"
 "strings"
 "syscall"
 "time"

 box "github.com/sagernet/sing-box"
 "github.com/sagernet/sing-box/option"
 M "github.com/sagernet/sing/common/metadata"
 sj "github.com/sagernet/sing/common/json"
)
const speedBytes int64=5*1024*1024
type probeResult struct {
 OK bool `json:"ok"`
 Error string `json:"error,omitempty"`
 DelayMS int64 `json:"delayMS,omitempty"`
 Bytes int64 `json:"bytes,omitempty"`
 MBps float64 `json:"MBps,omitempty"`
}
func measureProbe(ctx context.Context,client *http.Client,target string,speed bool) probeResult {
 started:=time.Now();request,e:=http.NewRequestWithContext(ctx,"GET",target,nil);if e!=nil{return probeResult{Error:"request_failed"}}
 request.Header.Set("Cache-Control","no-cache");request.Header.Set("Accept-Encoding","identity")
 response,e:=client.Do(request);if e!=nil {if ctx.Err()!=nil||errors.Is(e,context.DeadlineExceeded){return probeResult{Error:"cancelled_or_timeout"}};return probeResult{Error:"connection_or_tls_failed"}}
 defer response.Body.Close();delay:=time.Since(started).Milliseconds()
 if response.StatusCode!=200{return probeResult{Error:"unexpected_http_status"}}
 if !speed {
  data,e:=io.ReadAll(io.LimitReader(response.Body,4097));if e!=nil||len(data)>4096||!strings.Contains(string(data),"Success"){return probeResult{Error:"invalid_connectivity_response"}}
  return probeResult{OK:true,DelayMS:delay}
 }
 n,e:=io.Copy(io.Discard,io.LimitReader(response.Body,speedBytes+1))
 if e!=nil||n!=speedBytes{return probeResult{Error:"incomplete_download",Bytes:n}}
 // Include DNS, connection and TLS setup: report end-to-end application throughput.
 seconds:=time.Since(started).Seconds()
 return probeResult{OK:true,DelayMS:delay,Bytes:n,MBps:float64(n)/1e6/seconds}
}
func runProbe(data []byte,speed bool) probeResult {
 if validateDesktop(data)!=nil{return probeResult{Error:"configuration_rejected"}}
 ctx,stop:=signal.NotifyContext(desktopContext(),os.Interrupt,syscall.SIGTERM);defer stop()
 ctx,cancel:=context.WithTimeout(ctx,20*time.Second);defer cancel()
 parent:=os.Getppid()
 go func(){ticker:=time.NewTicker(time.Second);defer ticker.Stop();for{select{case <-ctx.Done():return;case <-ticker.C:if os.Getppid()!=parent{cancel();return}}}}()
 options,e:=sj.UnmarshalExtendedContext[option.Options](ctx,data);if e!=nil{return probeResult{Error:"configuration_rejected"}}
 options.Inbounds=nil;options.Log=&option.LogOptions{Disabled:true}
 service,e:=box.New(box.Options{Context:ctx,Options:options});if e!=nil{return probeResult{Error:"initialization_failed"}};defer service.Close()
 if e=service.Start();e!=nil{return probeResult{Error:"startup_failed"}}
 transport:=&http.Transport{Proxy:nil,DisableKeepAlives:true,DisableCompression:true,DialContext:func(ctx context.Context,network,address string)(net.Conn,error){return service.Outbound().Default().DialContext(ctx,network,M.ParseSocksaddr(address))}}
 defer transport.CloseIdleConnections()
 client:=&http.Client{Transport:transport,Timeout:15*time.Second,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}}
 target:="https://www.apple.com/library/test/success.html"
 if speed{target="https://speed.cloudflare.com/__down?bytes=5242880"}
 return measureProbe(ctx,client,target,speed)
}
func emitProbe(data []byte,speed bool){json.NewEncoder(os.Stdout).Encode(runProbe(data,speed))}
