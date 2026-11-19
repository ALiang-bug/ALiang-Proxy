package main

import (
 "bufio"
 "context"
 "time"
 "encoding/binary"
 "io"
 "net"
 "os"
 "path/filepath"
 "testing"
)

// Local Unix socket only: no TUN, root authorization, DNS or Internet access.
func TestTUNSessionInputBoundary(t *testing.T) {
 for _,oversized:=range []bool{false,true}{
  directory,e:=os.MkdirTemp("/private/tmp","pp-tun-");if e!=nil{t.Fatal(e)}
  defer os.RemoveAll(directory);path:=filepath.Join(directory,"control.sock")
  listener,e:=net.Listen("unix",path);if e!=nil{t.Fatal(e)}
  token:="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  done:=make(chan bool,1)
  go func(){
   c,e:=listener.Accept();if e!=nil{done<-false;return};defer c.Close()
   line,e:=bufio.NewReader(c).ReadString('\n');if e!=nil||line!=token+"\n"{done<-false;return}
   size:=uint32(2);if oversized{size=1<<20+1}
   binary.Write(c,binary.BigEndian,size);if !oversized{io.WriteString(c,"{}")};done<-true
  }()
  data,c,e:=readTunSession(path,token)
  if oversized {if e==nil{c.Close();t.Fatal("oversized session admitted")}} else {if e!=nil||string(data)!="{}"{t.Fatal("valid session rejected")};c.Close()}
  if !<-done{t.Fatal("session capability handshake failed")};listener.Close()
 }
}
func TestTUNSessionRejectsUntrustedPaths(t *testing.T){
 for _,path:=range []string{"/tmp/control.sock","/private/tmp/pp-tun-invalid/not-control","/etc/passwd"}{
  if _,c,e:=readTunSession(path,"short");e==nil{c.Close();t.Fatal("untrusted path accepted")}
 }
 directory,e:=os.MkdirTemp("/private/tmp","pp-tun-");if e!=nil{t.Fatal(e)};defer os.RemoveAll(directory)
 os.Chmod(directory,0755)
 if _,c,e:=readTunSession(filepath.Join(directory,"control.sock"),"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");e==nil{c.Close();t.Fatal("public session directory accepted")}
}

func TestTUNExclusiveLock(t *testing.T){
 path:=filepath.Join(t.TempDir(),"lock")
 first,e:=acquireTunLock(path);if e!=nil{t.Fatal(e)}
 if second,e:=acquireTunLock(path);e==nil{second.Close();t.Fatal("duplicate TUN session admitted")}
 first.Close();third,e:=acquireTunLock(path);if e!=nil{t.Fatal("lock not released")};third.Close()
 link:=filepath.Join(t.TempDir(),"link");os.Symlink(path,link);if f,e:=acquireTunLock(link);e==nil{f.Close();t.Fatal("symlink lock admitted")}
 os.Chmod(path,0644);if f,e:=acquireTunLock(path);e==nil{f.Close();t.Fatal("public lock admitted")}
}
func TestTUNConflictRoutes(t *testing.T){
 for _,text:=range []string{"default fe80::1 UGScg utun4","0/1 198.18.0.1 UGSc utun8","128.0/1 198.18.0.1 UGSc utun8","::/1 fe80::1 UGSc utun8"}{if !conflictingTunRoutes(text){t.Fatal("conflicting tunnel admitted")}}
 if conflictingTunRoutes("default 192.168.1.1 UGScg en0\nfe80::%utun0 link#10 UCI utun0"){t.Fatal("unrelated interface rejected")}
}

func TestTUNSessionDisconnectCancels(t *testing.T){
 client,server:=net.Pipe();defer client.Close()
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 go cancelOnTunSessionEnd(client,cancel);server.Close()
 select{case <-ctx.Done():case <-time.After(time.Second):t.Fatal("GUI disconnect did not cancel core context")}
}

func TestTUNScopedIPv6Defaults(t *testing.T){
 scoped:="default fe80::%utun0 UGcIg utun0\ndefault fe80::%utun2 UGcIg utun2"
 if conflictingTunRoutes(scoped){t.Fatal("scoped defaults mistaken for system capture")}
 if !conflictingTunRoutes(scoped+"\n128.0/1 198.18.0.0 UGSc utun4"){t.Fatal("scoped defaults hide real capture")}
}
