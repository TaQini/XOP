#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>

struct foo {
	char buffer[256];
	jmp_buf jb;
};

int main(int argc, char ** argv, char **envp) {
	struct foo *f = malloc(sizeof(*f));
	if (setjmp(f->jb)) {
		//printf("%d",sizeof(f->jb));
		return 0;
	}
	strcpy(f->buffer, argv[1]);
	longjmp(f->jb, 0xa);
}
