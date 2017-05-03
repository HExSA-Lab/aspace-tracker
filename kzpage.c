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

#include <net/sock.h>

#include "kzpage.h"
#include "kzparms.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kyle C. Hale");
MODULE_DESCRIPTION("Linux kernel module which catches mapping promotions from the zero page");
MODULE_VERSION("0.1");

#define ERROR(fmt, args...) printk(KERN_ERR "KZPAGE: " fmt, ##args)
#define INFO(fmt, args...)  printk(KERN_INFO "KZPAGE: " fmt, ##args)

#define NETLINK_USER 31

static struct sock *nl_sk = NULL;


static void
kzpage_recv_msg (struct sk_buff *skb) 
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Hello from kernel";
    int res;

    INFO("Receiving message...\n");

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr*)skb->data;

    INFO("Netlink received msg payload: %s\n", (char*)nlmsg_data(nlh));

    pid = nlh->nlmsg_pid;

    skb_out = nlmsg_new(msg_size, 0);

    if (!skb_out) {
        ERROR("Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid);

    if (res < 0) {
        ERROR("Error while sending response to user\n");
    }
}


static int __init 
kzpage_init (void) 
{
    struct netlink_kernel_cfg cfg;

    INFO("kzpage module starting up.\n");

    cfg.input = kzpage_recv_msg;
    cfg.groups = 1;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

    if (!nl_sk) {
        ERROR("Could not create netlink socket\n");
        return -10;
    }

    return 0;
}


static void __exit
kzpage_exit (void)
{
    INFO("kzpage module exiting.\n");
    netlink_kernel_release(nl_sk);
}

module_init(kzpage_init);
module_exit(kzpage_exit);
