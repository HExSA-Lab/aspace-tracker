/*
 * User-level interface for kzpage module
 *
 * (c) Kyle C. Hale 2017
 * Illinois Institute of Technology
 *
 *
 * Relies on: libnl 3.1 for netlink socket access
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pt_scan.h"


static void
usage (char ** argv)
{
    fprintf(stderr, "%s <pid>\n", argv[0]);
    exit(0);
}

int 
main (int argc, char * argv[])
{
    int pid;
    int fd;
    char buf[256];
    

    /* exit */
    if (argc != 2) {
        usage(argv);
    }

    pid = atoi(argv[1]);

    printf("Starting zpage daemon\n");

    usage(argv);

    return 0;
}

