#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(){
    // leak system addr
	void *s = *system;
    write(STDOUT_FILENO, &s, 8);

    // free point to write any mem
	void *p = 0x601018; // got of puts
	read(STDIN_FILENO, p, 8);

	puts("/bin/sh");
	return 0;
}
