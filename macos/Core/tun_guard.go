package main

import (
 "context"
 "errors"
 "os"
 "os/exec"
 "strings"
 "syscall"
 "time"
)
func conflictingTunRoutes(text string) bool {
 defaults:=map[string]bool{"default":true,"0/1":true,"128.0/1":true,"0.0.0.0/1":true,"128.0.0.0/1":true,"::/1":true,"8000::/1":true}
 for _,line:=range strings.Split(text,"\n") { fields:=strings.Fields(line);if len(fields)<4||!defaults[fields[0]]{continue};if fields[0]=="default"&&strings.Contains(fields[2],"I"){continue};if strings.HasPrefix(fields[3],"utun"){return true} }
 return false
}
func acquireTunLock(path string)(*os.File,error){
 fd,e:=syscall.Open(path,syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0600);if e!=nil{return nil,e}
 f:=os.NewFile(uintptr(fd),path);good:=false;defer func(){if !good{f.Close()}}()
 info,e:=f.Stat();if e!=nil{return nil,e};st,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||!info.Mode().IsRegular()||st.Uid!=uint32(os.Geteuid())||info.Mode().Perm()&0077!=0{return nil,errors.New("unsafe_tun_lock")}
 if e=syscall.Flock(fd,syscall.LOCK_EX|syscall.LOCK_NB);e!=nil{return nil,errors.New("tun_already_running")}
 good=true;return f,nil
}
func checkTunRoutes() error {
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
 data,e:=exec.CommandContext(ctx,"/usr/sbin/netstat","-rn").Output()
 if e!=nil||conflictingTunRoutes(string(data)){return errors.New("conflicting_tun_or_unavailable_routes")};return nil
}
