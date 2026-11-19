// PrivateProxy's desktop bridge. Credentials travel through stdin, never argv.
package main

import (
 "context"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "os/signal"
 "syscall"
 "time"
 "net"

 box "github.com/sagernet/sing-box"
 "github.com/sagernet/sing-box/option"
 "github.com/sagernet/sing-box/experimental/privateprofile"
 sj "github.com/sagernet/sing/common/json"
)
func fail(code string) { fmt.Fprintln(os.Stderr,code); os.Exit(1) }
func main() {
 var session net.Conn
 var data []byte
 var err error
 socketMode:=len(os.Args)==4&&os.Args[1]=="run-tun-socket"
 if socketMode {
  if os.Geteuid()!=0{fail("tun_requires_administrator")}
  data,session,err=readTunSession(os.Args[2],os.Args[3]);if err!=nil{fail("tun_session_failed")};defer session.Close()
 } else {
  if len(os.Args)!=2 { fail("invalid_command") }
  data,err=io.ReadAll(io.LimitReader(os.Stdin,privateprofile.MaxBytes+1)); if err!=nil || len(data)>privateprofile.MaxBytes { fail("invalid_input_size") }
 }
 if os.Args[1]=="probe"||os.Args[1]=="probe-speed" {emitProbe(data,os.Args[1]=="probe-speed");return}
 if os.Args[1]=="compile" {
  envelope,report,err:=privateprofile.Compile(data,[]string{"1.1.1.1"}); if err!=nil { fail(err.Error()) }
  json.NewEncoder(os.Stdout).Encode(map[string]any{"envelope":envelope,"report":report}); return
 }
 if os.Args[1]=="check-tun" {
  encoded,e:=tunConfiguration(data);if e!=nil{fail(e.Error())};if _,e=sj.UnmarshalExtendedContext[option.Options](desktopContext(),encoded);e!=nil{fail("invalid_tun_options")};fmt.Println("valid");return
 }
 tunMode:=os.Args[1]=="run-tun"||socketMode
 if os.Args[1]!="run"&&!tunMode { fail("invalid_command") }
 if tunMode&&os.Geteuid()!=0 { fail("tun_requires_administrator") }
 if validateDesktop(data)!=nil { fail("unsafe_desktop_configuration") }
 if tunMode {
  data,err=tunConfiguration(data);if err!=nil{fail(err.Error())}
  lock,e:=acquireTunLock("/var/run/local.privateproxy.tun.lock");if e!=nil{fail("tun_lock_unavailable")};defer lock.Close()
  if checkTunRoutes()!=nil{fail("conflicting_tun_or_unavailable_routes")}
 }
 ctx,cancel:=context.WithCancel(desktopContext()); defer cancel()
 if session!=nil{go cancelOnTunSessionEnd(session,cancel)}
 options,err:=sj.UnmarshalExtendedContext[option.Options](ctx,data); if err!=nil { fail("invalid_core_configuration") }
 expectedInbound:="mixed";if tunMode{expectedInbound="tun"}
 if len(options.Inbounds)!=1 || options.Inbounds[0].Type!=expectedInbound { fail("desktop_proxy_only") }
 options.Log=&option.LogOptions{Disabled:true}
 instance,err:=box.New(box.Options{Context:ctx,Options:options}); if err!=nil { fail("core_initialization_failed") }
 defer instance.Close()
 signals:=make(chan os.Signal,1); signal.Notify(signals,os.Interrupt,syscall.SIGTERM); defer signal.Stop(signals)
 if err=instance.Start();err!=nil { instance.Close();fail("core_start_failed") }
 if session!=nil{fmt.Fprintln(session,"ready")}else{fmt.Println("ready")}
 parent:=os.Getppid()
 ticker:=time.NewTicker(time.Second);defer ticker.Stop()
 for { select { case <-ctx.Done(): return; case <-signals: return; case <-ticker.C: if os.Getppid()!=parent { return } } }
}
