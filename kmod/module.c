
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

#include <asm/uaccess.h>

struct branch_info {
	unsigned long to;
	unsigned int count;

	struct rb_node node;
};

struct pmb_tracepoint {
	struct list_head list;

	struct kprobe probe;

	unsigned int len;
	/* Does this need locking? */
	struct rb_root branches;
};

static LIST_HEAD(tracepoints);

static struct kmem_cache *kmem_tracepoint, *kmem_branch_info;

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
	struct rb_node *node = tracepoint->branches.rb_node;

	if (tracepoint->probe.nmissed) {
		seq_printf(m, "0x%lx+0x%x->??? %ld 0 0\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->len,
			   tracepoint->probe.nmissed);
	}

	while (node) {
		struct branch_info *p = rb_entry(node, struct branch_info, node);

		seq_printf(m, "0x%lx+0x%x->0x%lx %d\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->len,
			   p->to,
			   p->count);

		node = rb_next(node);
	}
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
	unsigned long to = regs->ip;

	struct rb_root *root = &tracepoint->branches;
	struct rb_node **new = &root->rb_node, *parent = NULL;
	struct branch_info *p;

	while (*new) {

		p = rb_entry(*new, struct branch_info, node);

		parent = *new;
		if (to < p->to)
			new = &((*new)->rb_left);
		else if (to > p->to)
			new = &((*new)->rb_right);
		else
			break;
	}

	if (*new) { /* found it */
		p = rb_entry(*new, struct branch_info, node);
		p->count++;
	} else { /* allocate new */
		/* use kmem_cache */
		p = kmem_cache_alloc(kmem_branch_info, GFP_KERNEL);

		p->to = to;
		p->count = 1;

		rb_link_node(&p->node, parent, new);
		rb_insert_color(&p->node, root);
	}

	return;
}

static void
remove_tracepoint(struct pmb_tracepoint *tracepoint)
{
	struct rb_node *node = tracepoint->branches.rb_node;

	unregister_kprobe(&tracepoint->probe);
	list_del(&tracepoint->list);

	while (node) {
		struct rb_node *parent;

		while (node->rb_left || node->rb_right) {
			if (node->rb_left)
				node = node->rb_left;
			else
				node = node->rb_right;
		}

		parent = rb_parent(node);
		kmem_cache_free(kmem_branch_info,
				rb_entry(node, struct branch_info, node));

		if (!parent)
			break;

		if (node == parent->rb_left)
			parent->rb_left = NULL;
		else
			parent->rb_right = NULL;

		node = parent;
	}

	kmem_cache_free(kmem_tracepoint, tracepoint);
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

	tracepoint = kmem_cache_alloc(kmem_tracepoint, GFP_KERNEL);
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
			remove_tracepoint(tracepoint);
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
	if (!proc_poormanbts)
		return -ENOMEM;

	kmem_tracepoint = kmem_cache_create("poormanbts_tracepoint",
					     sizeof(struct pmb_tracepoint),
					     0, 0, NULL);
	if (!kmem_tracepoint)
		return -ENOMEM;

	kmem_branch_info = kmem_cache_create("poormanbts_branch_info",
					      sizeof(struct branch_info),
					      0, 0, NULL);
	if (!kmem_branch_info)
		return -ENOMEM;

	return 0;
}

void __exit exit_poormanbts(void)
{
	struct pmb_tracepoint *tracepoint, *tmp;
	proc_remove(proc_poormanbts);

	list_for_each_entry_safe(tracepoint, tmp, &tracepoints, list)
		remove_tracepoint(tracepoint);

	if (kmem_tracepoint)
		kmem_cache_destroy(kmem_tracepoint);

	if (kmem_branch_info)
		kmem_cache_destroy(kmem_branch_info);
}

module_init(init_poormanbts);
module_exit(exit_poormanbts);
MODULE_LICENSE("GPL");
