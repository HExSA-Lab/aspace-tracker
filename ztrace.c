/*
 * ztrace: user-level tool for tracking updates
 * to zero page mappings. Aided by the kztrace Linux
 * kernel module.
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
#include <ctype.h>
#include <wait.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <linux/netlink.h>
//#include <linux/uaccess.h>
//#include <asm-generic/uaccess.h>
#include <errno.h>
#include "kzparms.h"
#include "pt_scan.h"
#include "hashtable.h"


#define MAX_NUM_PT_ENTRIES 600000
#define TRACE_SHOULD_ATTACH 1
#define TRACE_NO_ATTACH     0

pid_t tracee;
int sock_fd = 0;

uint8_t DEBUG = 1;

#define DEBUG_PRINT(fmt, args...) \
    if (DEBUG) { \
        printf("<DEBUG> " fmt, ##args); \
    } 



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
    fprintf(stderr, "%s: must have PROG [ARGS] or -p PID\n"
                    "Try '%s -h' for more information.\n", 
                    argv[0], 
                    argv[0]);
    exit(1);
}


static void
version (char ** argv)
{
    printf("ztrace version %s\n\nKyle C. Hale (c) 2017\n", VERSION);
}


static void 
help (char ** argv)
{

    version(argv);

    printf("\nUsage: %s [-dhV] PROG [ARGS]\n"
            "   or: %s [-dhV] -p PID\n"
            "\n"
            "Options:\n"
            "%*s %-10s %s\n"
            "%*s %-10s %s\n"
            "%*s %-10s %s\n"
            "%*s %-10s %s\n",
            argv[0], 
            argv[0],
            2, "", "-p pid", "trace process with process id PID",
            2, "", "-h", "print help message",
            2, "", "-d", "enable debug output to stderr",
            2, "", "-V", "print version information"
          );

}


static unsigned
ztrace_hash_fn (addr_t key)
{
    return v3_hash_long(key, sizeof(void*));
}

static int
ztrace_eq_fn (addr_t key1, addr_t key2)
{
    return (key1 == key2);
}


/* 
 * user of this must free the msghdr
 *
 */
static struct msghdr*
setup_nl_msg (void *data, int len)
{
    struct nlmsghdr *nlh = NULL;
    struct msghdr *msg   = NULL;
    struct iovec * iov   = NULL;
    struct sockaddr_nl dst;

    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    dst.nl_pid    = 0; // sending to process
    dst.nl_groups = 0; // unicast

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

    msg->msg_name    = (void*)&dst;
    msg->msg_namelen = sizeof(dst);
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

static int
ztrace_send_msg (zp_msg_type_t type, void * arg)
{
    struct msghdr* m = NULL;
    zp_msg_t zpmsg;
    zp_msg_t * resp;
       
    memset(&zpmsg, 0, sizeof(zpmsg));
    
    zpmsg.arg = arg;
    zpmsg.type = type;

    /* TODO: doing this for every message is inefficient of course,
     * we should reuse the buffers */
    m = setup_nl_msg((void*)&zpmsg, sizeof(zpmsg));

    if (!m) {
        fprintf(stderr, "Could not setup netlink msg\n");
        return -1;
    }

    /* off to the kernel */
    sendmsg(sock_fd, m, 0);

    /* wait for the ack */
    recvmsg(sock_fd, m, 0);
    
    resp = (zp_msg_t*)NLMSG_DATA(m->msg_iov->iov_base);
    
    if (resp->type != ZP_MSG_ACK) {
        fprintf(stderr, "Received bad response from kernel (%d)\n", resp->type);
        return -1;
    }

    cleanup_msg(m);
    return 0;
}


static inline int
ztrace_send_reg_msg (unsigned long addr)
{
    return ztrace_send_msg(ZP_MSG_REG, (void*)addr);
}


static inline int
ztrace_send_init_msg (void)
{
    return ztrace_send_msg(ZP_MSG_INIT, NULL);
}


static inline int
ztrace_send_ack_msg (void)
{
    return ztrace_send_msg(ZP_MSG_ACK, NULL);
}

static inline int
ztrace_send_start_msg (int pid)
{
    int buff_size = MAX_NUM_PT_ENTRIES * sizeof(pt_data);
    pt_data *buff = (pt_data*) malloc(buff_size);

    if(buff ==NULL){
        fprintf(stderr, "could not create buffer");
        return -1 ;
    }
    memset(buff, 0, buff_size);

    struct start_msg_arg *arg = (struct start_msg_arg*)malloc(sizeof(struct start_msg_arg));  
    arg->pid = (void*)(uint64_t)pid;
    arg->buff = (void*)buff;

    int send_ret_val = 0;
    send_ret_val = ztrace_send_msg(ZP_MSG_START, (void*)arg);
    if(send_ret_val < 0){
        return send_ret_val;
    }

    //TODO:need to move this out of here
    int j;
    FILE *fp = fopen("testoutput.txt","w");
    for (j=0;j<MAX_NUM_PT_ENTRIES;j++) {
        if(buff[j].va == 0){
            DEBUG_PRINT("j-%d entries retrieved\n",j);
            fprintf(fp,"total %d \n",j);
            break;
        }

        fprintf(fp,"va %lx pa %lx \n",buff[j].va,buff[j].pa);
     }
     fclose(fp);
     return 0;
}

static inline int
ztrace_send_reset_msg (void)
{
    return ztrace_send_msg(ZP_MSG_RESET, NULL);
}


static struct hashtable*
find_all_zpages (int pid)
{
    uint64_t npages = 0;
    uint64_t zeros = 0;
    struct page_info *pi = NULL;

    struct hashtable *h = v3_create_htable(0, ztrace_hash_fn, ztrace_eq_fn);
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

    DEBUG_PRINT("Successfully scanned pages\n");

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

            /* notify the kmod of a page it needs to track */
            DEBUG_PRINT("zero page mapping at %p\n", (void*)zp->vaddr);
            ztrace_send_reg_msg((unsigned long)zp->vaddr);
            zeros++;
        }
    }

    DEBUG_PRINT("Found %lu zero page references on initial scan (%lu scanned)\n", zeros, npages);

    return h;
}


static void
die (int dontcare)
{
    printf("User interrupt...detaching from child\n");
    ztrace_send_reset_msg();
    ptrace(PTRACE_DETACH, tracee, 0, 0);
    kill(0, SIGKILL);
    exit(-1);
}


/*
 * waits for tracee to change state. 
 * Returns when it does, will
 * die if child exits.
 */
static void
waitonit (int pid)
{
    int status = 0;
    pid_t pw = waitpid(pid, &status, 0);

    if (pw == (pid_t) -1) {
        perror("ERROR: issue waiting for tracee");
        exit(1);
    }


    DEBUG_PRINT("Tracee got signal (%s)\n", strsignal(WSTOPSIG(status)));

    /* continue if we hit SIGRAPs */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        ptrace(PTRACE_CONT, pid, 0, 0);
    } else if (WIFEXITED(status)) {
        ztrace_send_reset_msg();
        fprintf(stderr, "Child exited with status %d\n",
                WEXITSTATUS(status));
        exit(0);
    } else if (WSTOPSIG(status) == SIGKILL ||
               WSTOPSIG(status) == SIGINT) {
        // we're done here, but pass along the signal first
        ztrace_send_reset_msg();
        ptrace(PTRACE_SYSCALL, pid, NULL, WSTOPSIG(status));
        printf("Child received interrupt, exiting.\n");
        exit(0);
    }
        
}

/*
 * this waits for a forked child to finish its execvp
 * sequence so that we can track the correct mm 
 * struct on the kernel side.
 */
static void
wait_for_exec_completion (int pid)
{
    int status = 0;
    uint64_t snum;
    struct user_regs_struct regs;

    
    printf("waiting for an exec\n");
    while (1) {

        ptrace(PTRACE_SYSCALL, pid, 0, 0);

        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("exiting in syscall wait\n");
            break;
        }

        ptrace(PTRACE_GETREGS, pid, 0, &regs);

        snum = regs.orig_rax;

        if (snum == SYS_execve) {
            break;

#if 0
            if (entering) {
                printf("child entering execve\n");
                entering = 0;
                break;
            } else {
                printf("child exiting execve\n");
                entering = 1;
                break;
            }
#endif

        }
    }
}



static void
cont (int pid)
{
    ptrace(PTRACE_CONT, pid, 0, 0);
}


static int 
force_trace (int pid)
{
    long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    if (ret < 0) {
        perror("Could not trace child process\n");
        return -1;
    }

    return 0;
}


static void
check_for_kmod (void)
{
    char buf[256];
    char fbuf[16];
    FILE *fd = NULL;

    memset(buf, 0, 256);
    sprintf(buf, "lsmod | grep %s", KMOD_NAME);

    fd = popen(buf, "r");

    if (!fd) {
        fprintf(stderr, "Couldn't check for module presence\n");
        exit(1);
    }


    if (fread(fbuf, 1, sizeof(fbuf), fd) > 0) { // we have a module
        DEBUG_PRINT("kztrace module detected\n");
        return;
    }

    fprintf(stderr, "kztrace module is not loaded, make sure to insert it\n");
    exit(1);

}


static void
setup_sock (void) 
{
    struct sockaddr_nl src_addr, dst_addr;

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
        return;
    }

    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
}




/* 
 * If we're not tracing a running process, we fork
 * off a new child and it will set itself up 
 * to be traced.
 *
 * idx is the index of the first non-flag argument passed
 * to *this* program, i.e. the name of the program 
 * to trace
 *
 */
static int
do_child (int argc, char ** argv, int idx)
{
    char * args[256];

    memcpy(args, argv+idx, (argc-idx+1)*sizeof(char*));
    args[(argc-idx+1)] = NULL; // marshalling for execvp

    ptrace(PTRACE_TRACEME); // we know we're about to be traced

    //kill(getpid(), SIGSTOP); // the tracer can now just use waitpid on us

    if (execvp(args[0], args) < 0) {
        perror("ERROR: could not exec process");
        return -1;
    }

    return 0;
}


static int 
do_trace (pid_t pid, int should_attach)
{
    struct hashtable *htable;

    /* 
     * if we're not tracing a forked process, 
     * we can simply attach to the proc and wait 
     * for it to stop.
     */
    if (should_attach) {
        if (force_trace(pid) != 0) {
            fprintf(stderr, "Could not trace target\n");
            return -1;
        }

        waitonit(pid);

    } else {
        /* 
         * otherwise, we need to wait until the forked 
         * proc is finished with since otherwise we'll 
         * be asking the kernel to watch the wrong mm 
         * struct when we send the start msg.
         */
         wait_for_exec_completion(pid);
    }


    /* we should detach if we die */
    signal(SIGINT, die);

    /* while it's stopped, find the current zero pages */
    htable = find_all_zpages(pid);

    if (!htable) {
        fprintf(stderr, "Error finding zero pages\n");
        exit(1);
    }

    /* tell the kernel it's time to start listening */
    ztrace_send_start_msg(pid);

    /* continue the process */
    cont(pid);

    /* let the thing go */
    while (1) {
        waitonit(pid);
        cont(pid);
    }

    return 0;
}


int 
main (int argc, char * argv[])
{
    pid_t pid;
    int pflag = 0;
    int hflag = 0;
    int vflag = 0;
    int c;

    if (argc < 2) {
        usage(argv);
    }

    while ((c = getopt(argc, argv, "hdVp:")) != -1) {
        switch (c) {
            case 'p':
                pflag = 1;
                pid = atoi(optarg);
                tracee = pid;
                break;
            case 'd':
                DEBUG = 1;
                break;
            case 'h':
                hflag = 1;
                break;
            case 'V':
                vflag = 1;
                break;
            case '?':
                if (optopt == 'p') 
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt)) 
                    fprintf(stderr, "Unknown option '-%c'.\n", optopt);
                else
                    fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
                return 1;
            default:
                abort();
            }
    }

    if (hflag) {
        help(argv);
        exit(0);
    }

    if (vflag) {
        version(argv);
        exit(0);
    }

    /* make sure the kern module is loaded */
    check_for_kmod();

    setup_sock();

    if (ztrace_send_init_msg() != 0) {
        fprintf(stderr, "Could not send init msg\n");
        return -1;
    }
        
    /* we need to fork a proc */
    if (!pflag) {

        DEBUG_PRINT("Forking a new child process\n");

        pid_t child = fork();

        if (child == 0) { 
            return do_child(argc, argv, optind);
        } else {
            return do_trace(child, TRACE_NO_ATTACH);
        }

    } else {

        DEBUG_PRINT("Tracing existing process (pid=%d)\n", pid);
        return do_trace(pid, TRACE_SHOULD_ATTACH);

    }

    return 0;
}

