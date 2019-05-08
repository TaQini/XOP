#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
    char buf[128];
    // leak func addr in libc
    void *q = *printf;
    write(STDOUT_FILENO, &q, 8);
    write(STDOUT_FILENO, "input\n",6);
    // stack overflow
    vulnerable_function();
    return 0;
}

