bof: gadget.o bof.c
	gcc -fno-stack-protector -no-pie bof.c gadget.o -o bof
gadget.o: gadget.s
	nasm -f elf64 gadget.s -o gadget.o
clean:
	rm gadget.o
