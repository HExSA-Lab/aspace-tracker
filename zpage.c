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
#include <string.h>


#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "kzparms.h"
#include "pt_scan.h"


static void
usage (char ** argv)
{
    fprintf(stderr, "%s <pid>\n", argv[0]);
    exit(0);
}


/* 
 * user of this must free the msghdr
 *
 */
static struct msghdr*
setup_nl_msg (void *data, int len, struct sockaddr_nl *dst_addr)
{
    struct nlmsghdr *nlh = NULL;
    struct msghdr *msg   = NULL;
    struct iovec * iov   = NULL;

    if (len > MAX_PAYLOAD) {
        fprintf(stderr, "Payload too big (max is %d)\n", MAX_PAYLOAD);
        return NULL;
    }


    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD));

    if (!nlh) {
        fprintf(stderr, "Could not allocate Netlink msg\n");
        return NULL;
    }

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));

    nlh->nlmsg_len   = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_flags = 0;

    memcpy(NLMSG_DATA(nlh), data, len);


    iov = (struct iovec*)malloc(sizeof(struct iovec));
    if (!iov) {
        fprintf(stderr, "Could not allocate iovec struct\n");
        goto out_err;
    }

    memset(iov, 0, sizeof(struct iovec));

    iov->iov_base = (void*)nlh;
    iov->iov_len  = nlh->nlmsg_len;
    
    msg = (struct msghdr*)malloc(sizeof(struct msghdr));

    if (!msg) {
        fprintf(stderr, "Could not allocate message header\n");
        goto out_err1;
    }
    
    memset(msg, 0, sizeof(struct msghdr));

    msg->msg_name    = (void*)dst_addr;
    msg->msg_namelen = sizeof(*dst_addr);
    msg->msg_iov     = iov;
    msg->msg_iovlen  = 1;

    return msg;

out_err1:
    free(iov);
out_err:
    free(nlh);
    return NULL;
}


static void
cleanup_msg (struct msghdr * msg)
{
    // free the netlink header
    free(msg->msg_iov->iov_base);

    // free the iovec
    free(msg->msg_iov);

    free(msg);
}


int 
main (int argc, char * argv[])
{
    int pid;
    int sock_fd;
    struct sockaddr_nl src_addr, dst_addr;
    struct msghdr* m = NULL;

    char * test = "Here is a test";


    /* exit */
    if (argc != 2) {
        usage(argv);
    }


    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = getpid(); 

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid    = 0; // sending to kernel
    dst_addr.nl_groups = 0; // unicast

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        fprintf(stderr, "Could not create Netlink socket\n");
        return -1;
    }

    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    m = setup_nl_msg((void*)test, strlen(test), &dst_addr);

    if (!m) {
        fprintf(stderr, "Could not setup netlink msg\n");
        return -1;
    }

    sendmsg(sock_fd, m, 0);

    printf("Waiting for response from kernel\n");

    recvmsg(sock_fd, m, 0);

    printf("Received message payload: %s\n", (char*)NLMSG_DATA(m->msg_iov->iov_base));

    pid = atoi(argv[1]);


    cleanup_msg(m);
    printf("Starting zpage daemon\n");



    return 0;
}

