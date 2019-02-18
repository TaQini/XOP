#!/usr/bin/python
import os
import sys
CMD = 'trans :zh-CN -b -no-warn '
msg = open(sys.argv[1]).read().splitlines()
for line in msg:
	print(line)
	os.system(CMD+'\''+line+'\'')

