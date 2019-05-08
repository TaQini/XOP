## vulner
 - buffer overflow
## attack
 - ret2libc
 - call2libc
 - rop
 - rop2(all libc gadget)
 - jop
## poc usage
 - [local ] `./exp.py`
 - [remote] `./exp.py [host] [port]`
## build
```
 $ make
```
start service:
```
 $ socat tcp-l:[port],fork exec:./bof
```
