
#include <linux/module.h>

int __init init_my_module(void)
{
	printk("HERE I GO!\n");
	return 0;
}
module_init(init_my_module);
