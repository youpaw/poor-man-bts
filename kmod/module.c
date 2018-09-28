
#define pr_fmt(fmt)	"poormanbts: " fmt

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

#include <asm/uaccess.h>

#include "common.h"

static int hack_can_probe=0;
module_param(hack_can_probe, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hack_can_probe, "Hack can_probe. You should know what you are doing.");

static int ignore_errors=0;
module_param(ignore_errors, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(ignore_errors, "Only report errors to dmesg and go on.");

static LIST_HEAD(tracepoints);

static struct kmem_cache *kmem_tracepoint, *kmem_branch_info;

static struct proc_dir_entry *proc_poormanbts;


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
	union {
		struct rb_root branches;
		struct {
			unsigned long to;
			unsigned int taken;
			unsigned int nottaken;
		};
	};
};

static inline int
poormanbts_tracepoint_is_dynamic_jump(struct pmb_tracepoint *tracepoint)
{
#define DYNAMIC_JUMP_OPCODE	0xff
	return tracepoint->probe.opcode == DYNAMIC_JUMP_OPCODE;
}

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
		seq_printf(m, "0x%lx+0x%x->??? %ld\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->len,
			   tracepoint->probe.nmissed);
	}

	if (!poormanbts_tracepoint_is_dynamic_jump(tracepoint)) {
		seq_printf(m, "0x%lx+0x%x->0x%lx %d\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->len,
			   (long)tracepoint->probe.addr + tracepoint->len,
			   tracepoint->nottaken);

		seq_printf(m, "0x%lx+0x%x->0x%lx %d\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->len,
			   tracepoint->to,
			   tracepoint->taken);
		return 0;
	}

	/* Dynamic jump */
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
poormanbts_tracepoint_add_dynamic(struct pmb_tracepoint *tracepoint,
				  long to)
{
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
}

static void
poormanbts_kprobe_post_handler(struct kprobe *probe,
			       struct pt_regs *regs,
			       unsigned long flags)
{
	struct pmb_tracepoint *tracepoint = container_of(probe, struct pmb_tracepoint, probe);
	unsigned long to = regs->ip;

	if (poormanbts_tracepoint_is_dynamic_jump(tracepoint)) {
		poormanbts_tracepoint_add_dynamic(tracepoint, to);
		return;
	}

	if (to == (long) tracepoint->probe.addr + tracepoint->len) {
		tracepoint->nottaken++;
	} else if (tracepoint->to == to) {
		tracepoint->taken++;
	} else if (tracepoint->to) {
		pr_warn("tracepoint->to was %lx -> new %lx\n",
			tracepoint->to, to);
		tracepoint->taken = tracepoint->nottaken = 0;
		tracepoint->to = to;
	} else /* if (!tracepoint->to) */ {
		tracepoint->to = to;
		tracepoint->taken++;
	}

	return;
}

static void
poormanbts_tracepoint_free(struct pmb_tracepoint *tracepoint)
{
	struct rb_node *node = tracepoint->branches.rb_node;

	unregister_kprobe(&tracepoint->probe);
	list_del(&tracepoint->list);

	if (!poormanbts_tracepoint_is_dynamic_jump(tracepoint))
		goto free;

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

free:
	kmem_cache_free(kmem_tracepoint, tracepoint);
}

static int
poormanbts_tracepoint_add(long addr, long size, long to)
{
	struct pmb_tracepoint *tracepoint;
	int ret;

	tracepoint = kmem_cache_alloc(kmem_tracepoint, GFP_KERNEL);
	if (tracepoint == NULL)
		return -ENOMEM;

	memset(tracepoint, 0, sizeof(*tracepoint));

	tracepoint->len = size;
	tracepoint->to = to;
	tracepoint->probe.pre_handler = poormanbts_kprobe_pre_handler;
	tracepoint->probe.post_handler = poormanbts_kprobe_post_handler;
	tracepoint->probe.addr = (void *)addr;
	INIT_LIST_HEAD(&tracepoint->list);

	ret = register_kprobe(&tracepoint->probe);
	if (ret < 0) {
		kmem_cache_free(kmem_tracepoint, tracepoint);
		return ret;
	}

	list_add(&tracepoint->list, &tracepoints);

	return 0;
}

static int
poormanbts_tracepoint_remove(long addr, long size)
{
	struct pmb_tracepoint *tracepoint;

	list_for_each_entry(tracepoint, &tracepoints, list) {
		if (tracepoint->probe.addr == (void *)addr &&
		    tracepoint->len == size) {
			poormanbts_tracepoint_free(tracepoint);
			return 0;
		}
	}

	return -ENOENT;
}

static ssize_t
poormanbts_handle_single_tracepoint(const char *buf, size_t count)
{
	const char *p;
	long addr, size;
	int ret;

	p = buf;
	if (*p == '-')
		p++;

	if (sscanf(p, "0x%lx+0x%lx", &addr, &size) != 2)
		return -EIO;

	if (*buf == '-')
		goto delete_entry;

	ret = poormanbts_tracepoint_add(addr, size, /*to*/0);
	if (ret)
		return ret;

	return count;

delete_entry:
	ret = poormanbts_tracepoint_remove(addr, size);
	if (ret)
		return ret;
	return count;
}

static ssize_t
poormanbts_handle_symbol(const char *name, size_t count)
{
	unsigned long addr, symbolsize;
	int ret;
	const char *buf, *end;
	char namebuf[256], *p;

	if (!strncmp(name, "addr:", 5)) {
		if (sscanf(name, "addr:0x%lx+0x%lx", &addr, &symbolsize) != 2)
			return -EINVAL;
	} else {
		addr = kallsyms_lookup_name(name);
		if (addr == 0)
			return -ENOENT;

		sprint_symbol(namebuf, addr);
		p = strchr(namebuf, '/');
		if (!p)
			return -EINVAL;

		*p = 0;
		p++;

		if (sscanf(p, "%lx", &symbolsize) != 1)
			return -EINVAL;
	}


	buf = (const char *)addr;
	end = buf + symbolsize;


	while (buf < end) {
		struct branch_op branch = {
			.opcode = 0,
			.from = (long) buf,
		};

		ret = branch_op_decode(&branch, &buf, end - buf);
		if (ret == -1) {
			pr_err("can't parse instruction at %p\n",
			       (void *)branch.from);
			return -EINVAL;
		}

		if (!ret)
			continue;

		ret = poormanbts_tracepoint_add(branch.from,
						branch.len,
						branch.to);
		if (ret < 0) {
			pr_err("can't install tracepoint at %p\n",
			       (void *)branch.from);
			if (ignore_errors)
				continue;
			return ret;
		}
	}

	return count;
}

static ssize_t
poormanbts_proc_handler_write(struct file *file,
			      const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	char buf[256], *p;
	ssize_t ret;

	if (copy_from_user(buf, buffer, min(count, sizeof(buf))))
		return -EFAULT;

	buf[count] = '\0';
	p = strchr(buf, '\n');
	if (p)
		*p = '\0';
	count = strlen(buf) + 1;

	ret = poormanbts_handle_single_tracepoint(buf, count);
	if (ret == -EIO)
		ret = poormanbts_handle_symbol(buf, count);

	return ret;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = poormanbts_proc_handlers_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = poormanbts_proc_handler_write,
	.release = seq_release,
};

asm ("\
my_return_one_start:\n\
	movq	$1, %rax\n\
	ret\n\
my_return_one_end:\n\
     ");

extern char my_return_one_start[], my_return_one_end[];

static void *(*my_text_poke)(void *addr, const void *opcode, size_t len);

static size_t orig_sizes;
static char can_probe_orig[16], kernel_text_address_orig[16];

static void
do_hack_can_probe(void)
{
	unsigned long addr;

	my_text_poke = (void *)kallsyms_lookup_name("text_poke");
	if (my_text_poke == NULL) {
		pr_err("can't find text_poke");
		return;
	}

	orig_sizes = my_return_one_end - my_return_one_start;

	pr_warn("You are hacking kprobes mechanism. God bless your soul");

	addr = kallsyms_lookup_name("can_probe");
	if (!addr)
		pr_err("can't find can_probe");
	else {
		memcpy(can_probe_orig, (void *)addr, orig_sizes);
		my_text_poke((void *)addr, my_return_one_start, orig_sizes);
	}

	addr = kallsyms_lookup_name("kernel_text_address");
	if (!addr)
		pr_err("can't find kernel_text_address");
	else {
		memcpy(kernel_text_address_orig, (void *)addr, orig_sizes);
		my_text_poke((void *)addr, my_return_one_start, orig_sizes);
	}
}

static void
undo_hack_can_probe(void)
{
	unsigned long addr;

	if (!orig_sizes || !my_text_poke) {
		pr_err("can't undo hack, was it done at all?");
		return;
	}

	addr = kallsyms_lookup_name("can_probe");
	if (addr)
		my_text_poke((void *)addr, can_probe_orig, orig_sizes);
	else
		pr_warn("can't restore can_probe orig");

	addr = kallsyms_lookup_name("kernel_text_address");
	if (addr)
		my_text_poke((void *)addr, kernel_text_address_orig, orig_sizes);
	else
		pr_warn("can't restore kernel_text_address orig");
}

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

	if (hack_can_probe)
		do_hack_can_probe();

	return 0;
}

void __exit exit_poormanbts(void)
{
	struct pmb_tracepoint *tracepoint, *tmp;
	proc_remove(proc_poormanbts);

	list_for_each_entry_safe(tracepoint, tmp, &tracepoints, list)
		poormanbts_tracepoint_free(tracepoint);

	if (kmem_tracepoint)
		kmem_cache_destroy(kmem_tracepoint);

	if (kmem_branch_info)
		kmem_cache_destroy(kmem_branch_info);

	if (hack_can_probe)
		undo_hack_can_probe();
}

module_init(init_poormanbts);
module_exit(exit_poormanbts);
MODULE_LICENSE("GPL");
