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
 */
#include <linux/module.h>
#include <linux/kernel.h>
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
MODULE_VERSION("0.1");

#define ERROR(fmt, args...) printk(KERN_ERR "KZTRACE: " fmt, ##args)
#define DEBUG(fmt, args...) printk(KERN_DEBUG "KZTRACE: " fmt, ##args)
#define INFO(fmt, args...)  printk(KERN_INFO "KZTRACE: " fmt, ##args)

#define NETLINK_USER 31

static struct sock *nl_sk = NULL;


/* 
 * this will be called when a pte changes in the target
 * process
 *
 */
static void
kztrace_change_pte (struct mmu_notifier *mn,
                   struct mm_struct *mm,
                   unsigned long address,
                   pte_t pte)
{
}

static struct mmu_notifier_ops mmn_ops = {
    .change_pte = kztrace_change_pte,
};

static struct mmu_notifier mmn;


static int
handle_start_msg (void * arg)
{
    struct task_struct * t = NULL;
    pid_t target_pid = (pid_t)(unsigned)(u64)arg;

    DEBUG("Handling START message\n");

    t = pid_task(find_vpid(target_pid), PIDTYPE_PID);

    if (!t) {
        ERROR("Could not get target PID for request\n");
        return -1;
    }

    DEBUG("Registering MMU notifier and tracking PTE updates...\n");

    mmn.ops = &mmn_ops;
    return mmu_notifier_register(&mmn, t->mm);
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
    DEBUG("Handling REG message\n");
    return 0;
}


static int
handle_reset_msg (void * arg)
{
    DEBUG("Handling RESET message\n");
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

    DEBUG("Receiving message...\n");

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

    //nlmsg_free(skb_out);
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
