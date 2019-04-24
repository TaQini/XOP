#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void foo(char *s, char *a, char **b){
    return;
}

void vunl(){
    char buf[128];
    read(STDIN_FILENO, buf, 512);
    fflush(stdin);
    foo(NULL,NULL,NULL);
}

int main(){
    // leak system addr
	void *s = *execve;
    write(STDOUT_FILENO, &s, 8);
    vunl();
	return 0;
}
