#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>

#define SLEEP_USEC 1000000

#define MMAP_SIZE 4096


#define NUM_MAPS 20

int main () {

    void * maps[NUM_MAPS];

    while (1) {

        int j;
        for (j = 0; j < NUM_MAPS; j++) {

            maps[j] = mmap(NULL, MMAP_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

            if (maps[j] == MAP_FAILED) {
                perror("Could not map region\n");
                return -1;
            }

            // read the page
            printf("x=%p\n", (void*)(*(unsigned long*)x));

            usleep(SLEEP_USEC);

            madvise(maps[j], MMAP_SIZE, MADV_RANDOM);

            printf("mapped page at %p\n", maps[j]);

            usleep(SLEEP_USEC);

            /* dirty the page */
            for (int i = 0; i < 4096; i++) {
                char * y = (char*)&maps[j];
                y[i] = 'a';
            }


            usleep(SLEEP_USEC);
        }

        /* now free them */
        for (j = 0; j < NUM_MAPS; j++) {
            munmap(maps[j], MMAP_SIZE);
        }
        usleep(SLEEP_USEC);

    }


}
