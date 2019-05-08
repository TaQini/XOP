## vulner
 - fromat string bug(assume)
## attack
 - got overwrite + jop
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

