fsb: gadget.o fsb.c
	gcc -fno-stack-protector -no-pie fsb.c gadget.o -o fsb
gadget.o: gadget.s
	nasm -f elf64 gadget.s -o gadget.o
clean:
	rm gadget.o
