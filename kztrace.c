/*
 * Zero page promotion detection module
 * (c) 2017 Kyle C. Hale
 * Illinois Institute of Technology
 *
 *
 * This kernel module will act as a server from which
 * a client program can request page updates (specifically
 * for zero pages)
 *
 * Original source: https://lwn.net/Articles/266320/
 * Changes as of 4.13: https://lwn.net/Articles/732952/
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/mmu_notifier.h>
#include <linux/pid.h>

#include <net/sock.h>

#include "kztrace.h"
#include "kzparms.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kyle C. Hale");
MODULE_DESCRIPTION("Linux kernel module which catches mapping promotions from the zero page");
MODULE_VERSION(VERSION);

#define ERROR(fmt, args...) printk(KERN_ERR "KZTRACE: " fmt, ##args)
#define DEBUG(fmt, args...) printk(KERN_DEBUG "KZTRACE: " fmt, ##args)
#define INFO(fmt, args...)  printk(KERN_INFO "KZTRACE: " fmt, ##args)

#define NETLINK_USER 31

static struct sock *nl_sk = NULL;
struct task_struct *target_task = NULL;


/* 
 * this will be called when a pte changes in the target
 * process
 *
 * TODO: this should be generalized
 *
 */
static void
kztrace_change_pte (struct mmu_notifier *mn,
                   struct mm_struct *mm,
                   unsigned long address,
                   pte_t pte)
{
    unsigned long zp_pa = virt_to_phys((volatile void*)empty_zero_page);

    INFO("pte change for %p\n", (void*)address);

    if (virt_to_phys((volatile void*)address) == zp_pa) {
        INFO("Zpage detected in address\n");
    }

    if ((zp_pa & ~(1<<12)) == (pte.pte & ~(1<<12))) {
        INFO("Zpage detected in pte\n");
    }

}


/*
 * can be invoked after the page-table entry for the page at address in the
 * address space indicated by mm has been removed, but while the page itself
 * still exists. 
 *
 * NOTE: NOT allowed to sleep
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
static void
kztrace_invalidate_page (struct mmu_notifier *mn, 
                         struct mm_struct *mm,
                         unsigned long address)
{
    INFO("page invalidation for %p\n", (void*)address);
}
#endif

static void
kztrace_release (struct mmu_notifier *mn,
                 struct mm_struct *mm)
{
    struct task_struct * t = mm->owner;

    INFO("release for mm notifier\n");

    if (t) {
        INFO("Release corresponds to pid %d\n", t->pid);
    }

    //mmu_notifier_unregister(&mmn, target_task->mm);
}

static int
kztrace_clear_flush_young (struct mmu_notifier *mn,
                           struct mm_struct *mm,
                           unsigned long start,
                           unsigned long end)
{
    INFO("clear flush young for %p-%p\n", (void*)start, (void*)end);
    return 0;
}

static int
kztrace_test_young (struct mmu_notifier *mn,
                    struct mm_struct *mm,
                    unsigned long address)
{
    INFO("test young for %p\n", (void*)address);
    return 0;
}


/*
In this case, invalidate_range_start() is called while all pages in the
affected range are still mapped; no more mappings for pages in the region
should be added in the secondary MMU after the call. When the unmapping is
complete and the pages have been freed, invalidate_range_end() is called to
allow any necessary cleanup to be done.

NOTE: allowed to sleep
*/
static void
kztrace_invalidate_range_start (struct mmu_notifier *mn,
                                struct mm_struct *mm,
                                unsigned long start,
                                unsigned long end)
{
    INFO("invalidate (start) for range %p-%p\n", (void*)start, (void*)end);
}

/*
This callback is invoked when a range of pages is actually being unmapped. It
can be called between calls to invalidate_range_start() and
invalidate_range_end(), but it can also be called independently of them in some
situations. One might wonder why both invalidate_page() and invalidate_range()
exist and, indeed, that is where the trouble started.

NOTE: NOT allowed to sleep
*/
static void
kztrace_invalidate_range (struct mmu_notifier *mn,
                          struct mm_struct *mm,
                          unsigned long start, 
                          unsigned long end)
{
    INFO("invalidate range %p-%p\n", (void*)start, (void*)end);
}

/*
 * NOTE: allowed to sleep
 */
static void
kztrace_invalidate_range_end (struct mmu_notifier *mn,
                              struct mm_struct *mm,
                              unsigned long start,
                              unsigned long end)
{
    INFO("invalidate (end) for range %p-%p\n", (void*)start, (void*)end);
}

// KCH NOTE: semantics of notifiers changes at 4.13
static struct mmu_notifier mmn;
static struct mmu_notifier_ops mmn_ops = {
    .change_pte             = kztrace_change_pte,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
    .invalidate_page        = kztrace_invalidate_page, 
#endif
    .release                = kztrace_release,
    .test_young             = kztrace_test_young,
    .clear_flush_young      = kztrace_clear_flush_young,
    .invalidate_range       = kztrace_invalidate_range,
    .invalidate_range_start = kztrace_invalidate_range_start,
    .invalidate_range_end   = kztrace_invalidate_range_end,
};


static int
handle_start_msg (void * arg)
{
    pid_t target_pid = (pid_t)(unsigned)(u64)arg;

    DEBUG("Handling START message for pid=%d\n", target_pid);

    target_task = pid_task(find_vpid(target_pid), PIDTYPE_PID);

    if (!target_task) {
        ERROR("Could not get target PID for request\n");
        return -1;
    }

    DEBUG("Registering MMU notifier and tracking PTE updates: mm is at %p\n", (void*)target_task->mm);

    mmn.ops = &mmn_ops;
    return mmu_notifier_register(&mmn, target_task->mm);
}


static int
handle_init_msg (void * arg)
{
    DEBUG("Handling INIT message\n");
    return 0;
}


static int
handle_ack_msg (void * arg)
{
    DEBUG("Handling ACK message\n");
    return 0;
}


static int 
handle_reg_msg (void * arg)
{
    unsigned long zp_va = (unsigned long)arg;

    DEBUG("Handling REG message for ZPVA=%p\n", (void*)zp_va);

    return 0;
}


static int
handle_reset_msg (void * arg)
{
    DEBUG("Handling RESET message\n");

    DEBUG("Unregistering MMU notifier (target_task=%p)\n", (void*)target_task);
    if (target_task) {
        target_task = NULL;
    } else {
        ERROR("Could not unregister notifier (task is NULL)\n");
        return -1;
    }


    return 0;
}


static int
handle_msg (void * data, int len)
{
    zp_msg_t * msg = (zp_msg_t*)data;

    switch (msg->type) {

        case ZP_MSG_INIT:
            return handle_init_msg(msg->arg);
        case ZP_MSG_START:
            return handle_start_msg(msg->arg);
        case ZP_MSG_ACK:
            return handle_ack_msg(msg->arg);
        case ZP_MSG_REG:
            return handle_reg_msg(msg->arg);
        case ZP_MSG_RESET:
            return handle_reset_msg(msg->arg);
        default:
            DEBUG("Received unhandled message type (%d)\n", msg->type);
            return -1;
    }

    return 0;
}


static void
kztrace_recv_msg (struct sk_buff *skb) 
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int res;
    zp_msg_t ack;
    ack.type = ZP_MSG_ACK;

    nlh = (struct nlmsghdr*)skb->data;

    if (handle_msg(nlmsg_data(nlh), nlmsg_len(nlh)) != 0) {
        ERROR("Could not handle Netlink message\n");
        return;
    } 

    pid = nlh->nlmsg_pid;

    skb_out = nlmsg_new(sizeof(ack), 0);

    if (!skb_out) {
        ERROR("Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(ack), 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(nlh), &ack, sizeof(ack));

    // send the ACK to userspace
    res = nlmsg_unicast(nl_sk, skb_out, pid);

    if (res < 0) {
        ERROR("Error while sending response to user\n");
    }

    // we don't need to free the skb, this will be taken care of for us
}


static int __init 
kztrace_init (void) 
{
    struct netlink_kernel_cfg cfg;

    INFO("kztrace module starting up.\n");

    cfg.input = kztrace_recv_msg;
    cfg.groups = 1;

#if !defined(CONFIG_MMU_NOTIFIER)
    ERROR("This module requires MMU notifier support\n");
    return -1;
#else

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

    if (!nl_sk) {
        ERROR("Could not create netlink socket\n");
        return -10;
    }

    return 0;

#endif
}


static void __exit
kztrace_exit (void)
{
    INFO("kztrace module exiting.\n");
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
    }
}

module_init(kztrace_init);
module_exit(kztrace_exit);
