/*
 * User-level interface for kzpage module
 *
 * (c) Kyle C. Hale 2017
 * Illinois Institute of Technology
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <wait.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "kzparms.h"
#include "pt_scan.h"
#include "hashtable.h"

pid_t tracee;

#define DEBUG 1

#if DEBUG==1
#define DEBUG_PRINT(fmt, args...) printf("<DEBUG> " fmt, ##args)
#else 
#define DEBUG_PRINT(fmt, args...)
#endif


typedef unsigned long addr_t;

typedef enum {
    ZP_INIT, /* zero page was present at the beginning */
    ZP_DYN,  /* this zpage entry was mapped at run time */
} zp_type_t;


struct zpinfo {
    zp_type_t type;
    uint64_t vaddr;
    unsigned refcnt;
};


static void
usage (char ** argv)
{
    fprintf(stderr, "%s <pid>\n", argv[0]);
    exit(0);
}


static unsigned
zpage_hash_fn (addr_t key)
{
    return v3_hash_long(key, sizeof(void*));
}

static int
zpage_eq_fn (addr_t key1, addr_t key2)
{
    return (key1 == key2);
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


static struct hashtable*
find_all_zpages (int pid)
{
    uint64_t npages = 0;
    uint64_t zeros = 0;
    struct page_info *pi = NULL;

    struct hashtable *h = v3_create_htable(0, zpage_hash_fn, zpage_eq_fn);
    if (!h) {
        fprintf(stderr, "Could not create zpage hashtable\n");
        return NULL;
    }

    if (pt_scan_get_page_infos_all_maps(pid, NULL, &npages)) {
        fprintf(stderr, "Failed to get number of pages\n");
        return NULL;
    }

    pi = (struct page_info*)malloc(sizeof(struct page_info)*npages);
    if (!pi) {
        fprintf(stderr, "Could not allocate page info array\n");
        return NULL;
    }
    memset(pi, 0, sizeof(struct page_info)*npages);

    if (pt_scan_get_page_infos_all_maps(pid, pi, &npages)) {
        fprintf(stderr, "Could not get pages\n");
        free(pi);
        return NULL;
    }

    printf("Successfully scanned pages\n");

    for (int i = 0; i < npages; i++) {
        if (pi[i].flags.flags.ZERO_PAGE == 1) {

            /* create a new entry */
            struct zpinfo * zp = malloc(sizeof(struct zpinfo));
            if (!zp) {
                fprintf(stderr, "Could not create zero page entry\n");
                return NULL;
            }
            memset(zp, 0, sizeof(struct zpinfo));

            zp->type   = ZP_INIT;
            zp->vaddr  = pi[i].va;
            zp->refcnt = pi[i].refcount;

            /* stash it */
            addr_t ret = v3_htable_insert(h, 
                                          (addr_t)zp->vaddr, 
                                          (addr_t)zp);

            if (!ret) {
                fprintf(stderr, "Could not insert zero page entry into hashtable\n");
                return NULL;
            }

            /* KCH HERE */
            zeros++;
        }
    }

    printf("Found %lu zero page references (%lu scanned)\n", zeros, npages);

    return h;
}


static void
die (int dontcare)
{
    printf("User interrupt...detaching from child\n");
    ptrace(PTRACE_DETACH, tracee, 0, 0);
    exit(-1);
}


/*
 * waits for tracee to change state. Returns when it does, will
 * die if child exits
 *
 */
static void
waitonit (int pid)
{
    int status;
    pid_t pw = wait(&status);

    if (pw == (pid_t) -1) {
        perror("issue waiting for tracee");
        exit(1);
    }

    if (WIFEXITED(status)) {
        fprintf(stderr, "Child exited with status %d\n",
                WEXITSTATUS(status));
    }

    DEBUG_PRINT("Tracee got signal (%d)\n", WSTOPSIG(status));

    if (WSTOPSIG(status) != SIGSTOP) {
        DEBUG_PRINT("passing signal along\n");
        ptrace(PTRACE_SYSCALL, pid, NULL, WSTOPSIG(status));
    }

    if (WSTOPSIG(status) == SIGKILL ||
        WSTOPSIG(status) == SIGINT) {
        // we're done here
        printf("Child received signal, exiting.\n");
        exit(0);
    }
        
}


static void
cont (int pid)
{
    ptrace(PTRACE_CONT, pid, 0, 0);
}


static int 
trace (int pid)
{
    long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    if (ret < 0) {
        perror("Could not trace child process\n");
        return -1;
    }

    /* wait for it to stop */
    waitonit(pid);

    return 0;
}


int 
main (int argc, char * argv[])
{
    int pid;
    int sock_fd;
    struct sockaddr_nl src_addr, dst_addr;
    struct msghdr* m = NULL;
    struct hashtable *htable;

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

    tracee = pid;

    printf("Starting zpage daemon (tracking pid %d)\n", pid);

    if (trace(pid) != 0) {
        fprintf(stderr, "Could not trace process\n");
        return -1;
    }

    /* we should detach if we die */
    signal(SIGINT, die);

    /* while it's stopped, find the current zero pages */
    htable = find_all_zpages(pid);

    if (!htable) {
        fprintf(stderr, "Error finding zero pages\n");
        exit(1);
    }

    /* continue the process */
    cont(pid);

    /* let the thing go */
    while (1) {
        waitonit(pid);
    }

    cleanup_msg(m);

    return 0;
}

