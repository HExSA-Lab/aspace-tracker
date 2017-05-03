/*
 * Zero page promotion detection module
 * (c) 2017 Kyle C. Hale
 * Illinois Institute of Technology
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>

#include "kzpage.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kyle C. Hale");
MODULE_DESCRIPTION("Linux kernel module which catches mapping promotions from the zero page");
MODULE_VERSION("0.1");

#define ERROR(fmt, args...) printk(KERN_ERR fmt, ##args)
#define INFO(fmt, args...)  printk(KERN_INFO fmt, ##args)




static int __init 
kzpage_init (void) 
{

    INFO("kzpage module starting.\n");

    return 0;
}


static void __exit
kzpage_exit (void)
{
    INFO("kzpage module exiting.\n");
}



module_init(kzpage_init);
module_exit(kzpage_exit);
