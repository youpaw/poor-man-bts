
#define pr_fmt(fmt)	"poormanbts: " fmt

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32) 
#include <linux/kallsyms.h>
#endif
#include <linux/uaccess.h>

#include "common.h"

static int hack_can_probe=0;
module_param(hack_can_probe, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hack_can_probe, "Hack can_probe. You should know what you are doing.");

static int ignore_errors=0;
module_param(ignore_errors, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(ignore_errors, "Only report errors to dmesg and go on.");

static unsigned long deactivate_threshold=-1UL;
module_param(deactivate_threshold, ulong, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(deactivate_threshold, "Deactivate probes that where hit that many times.");

static unsigned long sym_kallsyms_lookup_name=0;
module_param(sym_kallsyms_lookup_name, ulong, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(sym_kallsyms_lookup_name, "Address of kallsyms_lookup_name().");

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

	struct branch_op branch;

	struct work_struct work;

	struct rb_root branches;
	spinlock_t branches_lock;

	unsigned int taken;
	unsigned int nottaken;
};

/* TODO(pboldin) These should be named branch_is_dynamic / branch_is_uncond */
static inline int
poormanbts_tracepoint_is_dynamic(struct pmb_tracepoint *tracepoint)
{
	return  tracepoint->branch.type == INSN_JUMP_DYNAMIC ||
		tracepoint->branch.type == INSN_CALL_DYNAMIC;
}

static inline int
poormanbts_tracepoint_is_uncond(struct pmb_tracepoint *tracepoint)
{
	return  tracepoint->branch.type == INSN_JUMP_UNCONDITIONAL ||
		tracepoint->branch.type == INSN_CALL;
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
	char *type;

	switch (tracepoint->branch.type) {
	case INSN_CALL:
		type = "call";
		break;
	case INSN_CALL_DYNAMIC:
		type = "call_dynamic";
		break;
	case INSN_JUMP_DYNAMIC:
		type = "dynamic";
		break;
	case INSN_JUMP_UNCONDITIONAL:
		type = "uncond";
		break;
	case INSN_JUMP_CONDITIONAL:
		type = "cond";
		break;
	default:
		type = "unknown";
		break;
	}

	if (tracepoint->probe.nmissed) {
		seq_printf(m, "0x%lx+0x%x->??? %ld %s\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->branch.len,
			   tracepoint->probe.nmissed,
			   type);
	}

	if (!poormanbts_tracepoint_is_dynamic(tracepoint)) {

		if (!poormanbts_tracepoint_is_uncond(tracepoint)) {
			seq_printf(m, "0x%lx+0x%x->0x%lx %d %s\n",
				   (long)tracepoint->probe.addr,
				   tracepoint->branch.len,
				   (long)tracepoint->probe.addr + tracepoint->branch.len,
				   tracepoint->nottaken,
				   type);
		}

		seq_printf(m, "0x%lx+0x%x->0x%lx %d %s\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->branch.len,
			   tracepoint->branch.to,
			   tracepoint->taken,
			   type);
		return 0;
	}

	/* Dynamic jump */
	while (node) {
		struct branch_info *p = rb_entry(node, struct branch_info, node);

		seq_printf(m, "0x%lx+0x%x->0x%lx %d %s\n",
			   (long)tracepoint->probe.addr,
			   tracepoint->branch.len,
			   p->to,
			   p->count,
			   type);

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

static void
poormanbts_work_kprobe_disable(struct work_struct *work)
{
	struct pmb_tracepoint *tracepoint = container_of(work, struct pmb_tracepoint, work);
	disable_kprobe(&tracepoint->probe);
}

static void
poormanbts_tracepoint_disable(struct pmb_tracepoint *tracepoint)
{
	schedule_work(&tracepoint->work);
}

static struct rb_node **
poormanbts_find_branch_info(struct rb_root *root,
			    long to,
			    struct rb_node **pparent)
{
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

	if (pparent)
		*pparent = parent;

	return new;
}

static void
poormanbts_tracepoint_add_dynamic(struct pmb_tracepoint *tracepoint,
				  long to)
{
	struct rb_root *root = &tracepoint->branches;
	struct branch_info *p;
	struct rb_node **new, *parent;
	spinlock_t *lock = &tracepoint->branches_lock;

	spin_lock(lock);
	new = poormanbts_find_branch_info(root, to, &parent);

	if (*new) { /* found it */
found:
		p = rb_entry(*new, struct branch_info, node);
		p->count++;

	} else { /* allocate new */
		spin_unlock(lock);

		p = kmem_cache_alloc(kmem_branch_info, GFP_ATOMIC);
		if (!p) {
			pr_err("can't allocate memory for dynamic tracepoint: %p", tracepoint->branch.from);
			return;
		}

		p->to = to;
		p->count = 1;

		spin_lock(lock);

		new = poormanbts_find_branch_info(root, to, &parent);
		/* We lost the race */
		if (*new) {
			kmem_cache_free(kmem_branch_info, p);
			goto found;
		}

		rb_link_node(&p->node, parent, new);
		rb_insert_color(&p->node, root);

	}

	spin_unlock(lock);
}

static unsigned long reg_to_offset[] = {
#define REG(x)	offsetof(struct pt_regs, x)
	[0]	=	REG(ax),
	[1]	=	REG(cx),
	[2]	=	REG(dx),
	[3]	=	REG(bx),
	[4]	=	REG(sp),
	[5]	=	REG(bp),
	[6]	=	REG(si),
	[7]	=	REG(di),

#define	REG2(x)	[x]	=	REG(r ## x)
	REG2(8),
	REG2(9),
	REG2(10),
	REG2(11),
	REG2(12),
	REG2(13),
	REG2(14),
	REG2(15),
	[REG_RIP]	=	REG(ip),
#undef REG
#undef REG2
};


static long
poormanbts_read_reg(int reg, void *data)
{
	return *(long *)(data + reg_to_offset[reg]);
}

static long
poormanbts_read_mem(long mem, void *arg)
{
	return *(long *)mem;
}

/* TODO(pboldin): this should be shared into common.c */
static int
poormanbts_kprobe_pre_handler(struct kprobe *probe,
			      struct pt_regs *regs)
{
	struct pmb_tracepoint *tracepoint = container_of(probe, struct pmb_tracepoint, probe);
	int cond;

	if (poormanbts_tracepoint_is_dynamic(tracepoint)) {
		long to = branch_op_resolve_to(&tracepoint->branch,
					       poormanbts_read_reg,
					       poormanbts_read_mem,
					       (void *)regs);
		poormanbts_tracepoint_add_dynamic(tracepoint, to);
		tracepoint->taken += 2;
	} else {
		cond = branch_op_check_condition(&tracepoint->branch,
						 regs->flags,
						 regs->cx);

		if (cond)
			tracepoint->taken++;
		else
			tracepoint->nottaken++;
	}

	if (deactivate_threshold != -1UL) {
		long sum = tracepoint->taken + tracepoint->nottaken;

		if ((tracepoint->taken && tracepoint->nottaken
		     && sum >= deactivate_threshold) ||
		    sum >= 2 * deactivate_threshold)
			poormanbts_tracepoint_disable(tracepoint);
	}

	return 0;
}

static void
poormanbts_tracepoint_free(struct pmb_tracepoint *tracepoint)
{
	struct rb_node *node = tracepoint->branches.rb_node;

	unregister_kprobe(&tracepoint->probe);
	list_del(&tracepoint->list);

	if (!poormanbts_tracepoint_is_dynamic(tracepoint))
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
poormanbts_tracepoint_add_branch(struct branch_op *branch)
{
	struct pmb_tracepoint *tracepoint;
	int ret;

	long addr = branch->from;

	tracepoint = kmem_cache_alloc(kmem_tracepoint, GFP_KERNEL);
	if (tracepoint == NULL)
		return -ENOMEM;

	memset(tracepoint, 0, sizeof(*tracepoint));

	INIT_LIST_HEAD(&tracepoint->list);
	tracepoint->branches = RB_ROOT;
	spin_lock_init(&tracepoint->branches_lock);

	tracepoint->probe.addr = (void *)addr;
	tracepoint->branch = *branch;
	tracepoint->probe.pre_handler = poormanbts_kprobe_pre_handler;

	INIT_WORK(&tracepoint->work, poormanbts_work_kprobe_disable);

	ret = register_kprobe(&tracepoint->probe);
	if (ret < 0) {
		kmem_cache_free(kmem_tracepoint, tracepoint);
		return ret;
	}

	list_add_tail(&tracepoint->list, &tracepoints);

	return 0;
}

static int
poormanbts_tracepoint_add(long addr, long size, long to)
{
	struct branch_op branch = {
		.from = addr,
		.to = to,
		.len = size,
		.type = INSN_OTHER,
	};

	return poormanbts_tracepoint_add_branch(&branch);
}

static int
poormanbts_tracepoint_remove(long addr, long size)
{
	struct pmb_tracepoint *tracepoint;

	list_for_each_entry(tracepoint, &tracepoints, list) {
		if (tracepoint->probe.addr == (void *)addr &&
		    tracepoint->branch.len == size) {
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#define my_kallsyms_lookup_name kallsyms_lookup_name
#else
static unsigned long my_kallsyms_lookup_name(const char *name)
{
        unsigned long addr = 0;

		if (!sym_kallsyms_lookup_name) {
			pr_err("kallsyms_lookup_name() symbol was not specified.\n");
			return 0;
		}
		unsigned long (*my_kallsyms_lookup_name)(char *name) = sym_kallsyms_lookup_name;
		addr = my_kallsyms_lookup_name(name);
		return addr;
}
#endif

static bool (*my_within_kprobe_blacklist)(unsigned long addr);
static unsigned long my___kprobes_text_start, my___kprobes_text_end;

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
		addr = my_kallsyms_lookup_name(name);
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

	if ((
	     addr >= (unsigned long)my___kprobes_text_start &&
	     addr < (unsigned long)my___kprobes_text_end
	     ) ||
	    (my_within_kprobe_blacklist && my_within_kprobe_blacklist(addr))) {
		pr_warn("ignoring '%s', as it is within kprobes\n",
			name);
		return 0;
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

		switch (branch.type) {
		case INSN_JUMP_UNCONDITIONAL:
		case INSN_CALL:
		case INSN_CALL_DYNAMIC:
		/**
		 * cover jump_dynamic -- this is how switch/case is implemented
		 */
			continue;
		}

		ret = poormanbts_tracepoint_add_branch(&branch);
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

	count = min(count, sizeof(buf));
	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	buf[min(count, sizeof(buf) - 1)] = '\0';
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

/* TODO(pboldin): fix our code and remove this hack */
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

	my_text_poke = (void *)my_kallsyms_lookup_name("text_poke");
	if (my_text_poke == NULL) {
		pr_err("can't find text_poke");
		return;
	}

	orig_sizes = my_return_one_end - my_return_one_start;

	pr_warn("You are hacking kprobes mechanism. God bless your soul\n");

	addr = my_kallsyms_lookup_name("can_probe");
	if (!addr)
		pr_err("can't find can_probe");
	else {
		memcpy(can_probe_orig, (void *)addr, orig_sizes);
		my_text_poke((void *)addr, my_return_one_start, orig_sizes);
	}

	addr = my_kallsyms_lookup_name("kernel_text_address");
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

	addr = my_kallsyms_lookup_name("can_probe");
	if (addr)
		my_text_poke((void *)addr, can_probe_orig, orig_sizes);
	else
		pr_warn("can't restore can_probe orig");

	addr = my_kallsyms_lookup_name("kernel_text_address");
	if (addr)
		my_text_poke((void *)addr, kernel_text_address_orig, orig_sizes);
	else
		pr_warn("can't restore kernel_text_address orig");
}

int __init init_poormanbts(void)
{
	my___kprobes_text_start = my_kallsyms_lookup_name("__kprobes_text_start");
	my___kprobes_text_end = my_kallsyms_lookup_name("__kprobes_text_end");
	my_within_kprobe_blacklist = (void *)my_kallsyms_lookup_name("within_kprobe_blacklist");
	if (!my___kprobes_text_start || !my___kprobes_text_end)
		return -ENOENT;

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

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)
	remove_proc_entry("poormanbts", NULL);
#else
	proc_remove(proc_poormanbts);
#endif
	/* TODO(pboldin): do bulk unregister here */
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
