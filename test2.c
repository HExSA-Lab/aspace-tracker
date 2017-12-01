#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>

#define SLEEP_USEC 1000000

#define MMAP_SIZE 4096

int main () {


    while (1) {
        void * x = mmap(NULL, MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

        if (x == MAP_FAILED) {
            perror("Could not map region\n");
            return -1;
        }

        printf("mapped page at %p\n", x);

	// read the page
	printf("x=%p\n", (void*)(*(unsigned long*)x));

        usleep(SLEEP_USEC);

        /* dirty the page */
        for (int i = 0; i < 4096; i++) {
            char * y = (char*)x;
            y[i] = 'a';
        }


        usleep(SLEEP_USEC);

#if 0
        munmap(x, MMAP_SIZE);

        usleep(SLEEP_USEC);
#endif
    }


}
