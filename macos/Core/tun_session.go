package main

import (
 "bufio"
 "context"
 "encoding/binary"
 "encoding/hex"
 "errors"
 "io"
 "net"
 "os"
 "path/filepath"
 "strings"
 "syscall"
 "time"
)

// The root helper is a client of a one-shot user-owned local socket, never a
// privileged listener. A random capability authenticates it to the GUI.
func readTunSession(path, capability string) ([]byte,net.Conn,error) {
 reject:=func()([]byte,net.Conn,error){return nil,nil,errors.New("invalid_tun_session")}
 if !strings.HasPrefix(path,"/private/tmp/pp-tun-")||filepath.Base(path)!="control.sock"||len(capability)!=64{return reject()}
 if _,e:=hex.DecodeString(capability);e!=nil{return reject()}
 parent,e:=os.Lstat(filepath.Dir(path));if e!=nil||!parent.IsDir()||parent.Mode().Perm()&0077!=0{return reject()}
 info,e:=os.Lstat(path);if e!=nil||info.Mode()&os.ModeSocket==0{return reject()}
 ps,ok:=parent.Sys().(*syscall.Stat_t);if !ok{return reject()};ss,ok:=info.Sys().(*syscall.Stat_t);if !ok||ps.Uid!=ss.Uid{return reject()}
 conn,e:=net.DialTimeout("unix",path,10*time.Second);if e!=nil{return nil,nil,e}
 good:=false;defer func(){if !good{conn.Close()}}()
 conn.SetDeadline(time.Now().Add(15*time.Second))
 if _,e=io.WriteString(conn,capability+"\n");e!=nil{return nil,nil,e}
 reader:=bufio.NewReader(conn);var size uint32
 if e=binary.Read(reader,binary.BigEndian,&size);e!=nil||size==0||size>1<<20{return reject()}
 data:=make([]byte,size);if _,e=io.ReadFull(reader,data);e!=nil{return nil,nil,e}
 conn.SetDeadline(time.Time{});good=true
 return data,conn,nil
}

func cancelOnTunSessionEnd(conn net.Conn,cancel context.CancelFunc){var b [1]byte;conn.Read(b[:]);cancel()}
