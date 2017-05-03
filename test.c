#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>

int main () {

    int z;
    size_t size = 4096*1000;
    void * x = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if (x == MAP_FAILED) {
        perror("Could not map region\n");
        return -1;
    }

    for (int i = 0; i < (4096*1000)/sizeof(int); i++) {
        int * y = (int*)x;
        z = y[i];
    }


    while (1) {
        sleep(1);
    }

}
