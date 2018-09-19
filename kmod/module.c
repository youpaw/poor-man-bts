
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

struct pmb_tracepoint {
	struct list_head list;

	struct kprobe probe;

	unsigned int len;
	unsigned int taken;
	unsigned int nottaken;
};


static LIST_HEAD(tracepoints);

static struct proc_dir_entry *proc_poormanbts;

static void *
poormanbts_seq_start(struct seq_file *m,
		     loff_t *pos)
{
	return seq_list_start(&tracepoints, *pos);
}

static void
poormanbts_seq_stop(struct seq_file *m,
		    void *v)
{
	return;
}

static void *
poormanbts_seq_next(struct seq_file *m,
		    void *v,
		    loff_t *ppos)
{
	return seq_list_next(v, &tracepoints, ppos);
}

static int
poormanbts_seq_show(struct seq_file *m,
		    void *v)
{
	struct pmb_tracepoint *tracepoint =
		list_entry(v, struct pmb_tracepoint, list);

	seq_printf(m, "0x%lx+0x%x %ld %d %d\n",
		   (long)tracepoint->probe.addr,
		   tracepoint->len,
		   tracepoint->probe.nmissed,
		   tracepoint->taken,
		   tracepoint->nottaken);
	return 0;
}

static const struct seq_operations poormanbts_seq_ops = {
	.start = poormanbts_seq_start,
	.stop = poormanbts_seq_stop,
	.show = poormanbts_seq_show,
	.next = poormanbts_seq_next,
};

static int
poormanbts_proc_handlers_open(struct inode *inode,
			      struct file *file)
{
	return seq_open(file, &poormanbts_seq_ops);
}

static int
poormanbts_kprobe_pre_handler(struct kprobe *probe,
			      struct pt_regs *regs)
{
	return 0;
}

static void
poormanbts_kprobe_post_handler(struct kprobe *probe,
			       struct pt_regs *regs,
			       unsigned long flags)
{
	struct pmb_tracepoint *tracepoint = container_of(probe, struct pmb_tracepoint, probe);

	if (regs->ip == (long)tracepoint->probe.addr + tracepoint->len)
		tracepoint->nottaken++;
	else
		tracepoint->taken++;

	return;
}

static ssize_t
poormanbts_proc_handler_write(struct file *file,
			      const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	char buf[256], *p;
	long addr, size;
	int ret;
	struct pmb_tracepoint *tracepoint;

	if (copy_from_user(buf, buffer, min(count, sizeof(buf))))
		return -EFAULT;

	buf[count] = '\0';
	p = strchr(buf, '\n');
	if (p)
		*p = '\0';
	count = strlen(buf) + 1;

	p = buf;
	if (*p == '-')
		p++;

	if (sscanf(p, "0x%lx+0x%lx", &addr, &size) != 2)
		return -EIO;

	if (*buf == '-')
		goto delete_entry;

	tracepoint = kmalloc(sizeof(*tracepoint), GFP_KERNEL);
	if (tracepoint == NULL)
		return -ENOMEM;

	memset(tracepoint, 0, sizeof(*tracepoint));

	tracepoint->len = size;
	tracepoint->probe.pre_handler = poormanbts_kprobe_pre_handler;
	tracepoint->probe.post_handler = poormanbts_kprobe_post_handler;
	tracepoint->probe.addr = (void *)addr;
	INIT_LIST_HEAD(&tracepoint->list);

	ret = register_kprobe(&tracepoint->probe);
	if (ret < 0) {
		kfree(tracepoint);
		return -EINVAL;
	}

	list_add(&tracepoint->list, &tracepoints);

	return count;

delete_entry:
	list_for_each_entry(tracepoint, &tracepoints, list) {
		if (tracepoint->probe.addr == (void *)addr &&
		    tracepoint->len == size) {

			unregister_kprobe(&tracepoint->probe);
			list_del(&tracepoint->list);
			kfree(tracepoint);

			return count;
		}
	}
	return -ENOENT;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = poormanbts_proc_handlers_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = poormanbts_proc_handler_write,
	.release = seq_release,
};

int __init init_poormanbts(void)
{
	proc_poormanbts = proc_create("poormanbts", 0600,
				      NULL, &fops);
	return 0;
}

void __exit exit_poormanbts(void)
{
	struct pmb_tracepoint *tracepoint;
	proc_remove(proc_poormanbts);
	list_for_each_entry(tracepoint, &tracepoints, list)
		unregister_kprobe(&tracepoint->probe);
}

module_init(init_poormanbts);
module_exit(exit_poormanbts);
MODULE_LICENSE("GPL");
