#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void g1(){
	__asm__("xor %rdi,%rdi");
    __asm__("xor %rsi,%rsi");
    __asm__("xor %rdx,%rdx");
    __asm__("xor %rax,%rax");

    __asm__("pop %rcx");
	__asm__("jmp *0x0(%rsp)");
}
void g2(){
    __asm__("push %rax");
    __asm__("movabs $0x68732f2f6e69622f,%rbx");
    __asm__("push %rbx");
    __asm__("mov %rsp,%rdi");

	__asm__("jmp *0x18(%rsp)");
}
void g3(){
	__asm__("mov $0x3b,%rax");
	__asm__("jmp *0x20(%rsp)");
} 

void g4(){
	__asm__("syscall");
}

void dispatch(){
	__asm__("jmp *0x0(%rsp)");
}

int main(int argc, char** argv) {
    char buf[128];
    // leak func addr in libc
    void *q = *printf;
    write(STDOUT_FILENO, &q, 8);
    write(STDOUT_FILENO, "input\n",6);
    // stack overflow
    read(STDIN_FILENO, buf, 512);
    return 0;
}

