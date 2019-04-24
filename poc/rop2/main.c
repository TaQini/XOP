#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
    char buf[128];
    void *p = *printf;
    write(STDOUT_FILENO, &p, 8);
    write(STDOUT_FILENO, "input\n",6);
    read(STDIN_FILENO, buf, 512);
    return 0;
}
