
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/user.h>

#include <kpatch_process.h>
#include <kpatch_log.h>
#include <kpatch_ptrace.h>

#include "eflags.h"
#include "common.h"

static int install_trace_point(kpatch_process_t *child,
			       struct pmb_tracepoint *tpoint)
{
	int rv;
	static char bkpnt_insn[] = { 0xcc };
	long dst = tpoint->branch.from;

	rv = kpatch_process_mem_read(child,
				     dst,
				     tpoint->orig,
				     sizeof(tpoint->orig));

	if (rv < 0)
		return rv;

	rv = kpatch_process_mem_write(child,
				      bkpnt_insn,
				      dst,
				      sizeof(bkpnt_insn));
	if (rv < 0)
		return rv;

	return 0;
}

static int qsort_compare(const void *a_, const void *b_)
{
	const struct pmb_tracepoint *a = a_;
	const struct pmb_tracepoint *b = b_;

	if (a->branch.from < b->branch.from)
		return -1;
	else if (a->branch.from == b->branch.from)
		return 0;
	else
		return 1;
}

const char *objname = NULL;

static int install_trace_points(kpatch_process_t *child, struct pmb_tracepoint *tpoints, size_t npoints)
{
	int ret = -1;
	struct pmb_tracepoint *p;
	size_t i;
	long obj_load_addr = 0;
	kpatch_object_file_t *obj;

	for (i = 0, p = tpoints; i < npoints; i++, p++) {
		if (objname != p->objname) {
			objname = p->objname;

			obj = kpatch_process_get_obj_by_regex(child, objname);
			if (!obj) {
				printf("can't find object %s\n", objname);
				goto out;
			}
			obj_load_addr = obj->load_offset;
			printf("objname = %s, load_addr = %lx\n",
			       objname, obj_load_addr);
		}

		p->branch.from += obj_load_addr;

		ret = install_trace_point(child, p);
		if (ret < 0) {
			printf("Can't install tracepoint at %lx\n",
			       p->branch.from);
			goto out;
		}
	}

	qsort(tpoints, npoints, sizeof(*tpoints), qsort_compare);

	ret = 0;
out:
	return ret;
}

static int attach_to_process(kpatch_process_t *child, char * const *argv)
{
	int ret, status;
	pid_t pid, waited;
	int sv[2];

	ret = socketpair(AF_LOCAL, SOCK_STREAM, 0, sv);
	if (ret < 0) {
		perror("socketpair");
		return ret;
	}

	pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
	} else if (pid == 0) {
		recv(sv[0], &ret, sizeof(ret), 0);
		asm (".align 8; int $3; .align 8");
		return execvp(argv[0], argv);
	}

	ret = kpatch_process_init(child, pid, 1, sv[1]);
	if (ret < 0) {
		perror("kpatch_process_init");
		return -1;
	}

	ret = kpatch_process_load_libraries(child);
	if (ret < 0) {
		perror("kpatch_process_load_libraries");
		return -1;
	}

	ret = kpatch_process_map_object_files(child);
	if (ret < 0) {
		perror("kpatch_process_map_object_files");
		return -1;
	}

	return 0;
}

unsigned long reg_to_offset[] = {
#define REG(x)	offsetof(struct user_regs_struct, x)
	[0]	=	REG(rax),
	[1]	=	REG(rcx),
	[2]	=	REG(rdx),
	[3]	=	REG(rbx),
	[4]	=	REG(rsp),
	[5]	=	REG(rbp),
	[6]	=	REG(rsi),
	[7]	=	REG(rdi),
	[32]	=	REG(rip),
#undef REG
};



static bool trace_point_check_condition(struct pmb_tracepoint *tpoint,
					kpatch_process_t *child,
					int pid)
{
	unsigned long eflags;

	eflags = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user_regs_struct, eflags), NULL);

#define	FLAG(x)	(eflags & X86_EFLAGS_ ## x)
	switch (tpoint->branch.opcode) {
	case	0x77: /* ja or jnbe */
		return	!FLAG(CF) && !FLAG(ZF);

	case	0x73: /* jae or jnc or jnb */
		return	!FLAG(CF);

	case	0x72: /* jb or jc or jnae */
		return	FLAG(CF);

	case	0x76: /* jbe or jna */
		return	FLAG(CF) || FLAG(ZF);

	case	0x74: /* je or jz */
		return	FLAG(ZF);

	case	0x7f: /* jg or jnle */
		return	!FLAG(ZF) && FLAG(SF) == FLAG(OF);

	case	0x7d: /* jge or jnl */
		return	FLAG(SF) == FLAG(OF);

	case	0x7c: /* jl or jnge */
		return	FLAG(SF) != FLAG(OF);

	case	0x7e: /* jle or jng */
		return	FLAG(ZF) || FLAG(SF) != FLAG(OF);

	case	0x75: /* jne or jnz */
		return	!FLAG(ZF);

	case	0x71: /* jno */
		return	!FLAG(OF);

	case	0xe3: /* jcxz/jecxz/jrcxz */
		return	!!ptrace(PTRACE_PEEKUSER, pid,
				 offsetof(struct user_regs_struct, rcx), NULL);

	case	0x7b: /* jnp or jpo */
		return	!FLAG(PF);

	case	0x79: /* jns */
		return	!FLAG(SF);

	case	0x7a: /* jp or jpe */
		return	FLAG(PF);

	case	0x78: /* js */
		return	FLAG(SF);

	case	0x70: /* jo */
		return	FLAG(OF);

	case	0xe9:
	case	0xeb:
	case	JUMP_OP_OPCODE_DYNAMIC:
		/* unconditional jumps */
		return true;
	default:
		printf("unknown opcode %x\n", tpoint->branch.opcode);
		abort();
	}
}

static long trace_point_resolve_to(struct pmb_tracepoint *tpoint,
				   kpatch_process_t *child,
				   int pid, long rip)
{
	bool is_ref = tpoint->branch.dynamic_reg & JUMP_OP_DYNAMIC_REG_REF;
	bool is_sib = tpoint->branch.dynamic_sib_mult;
	int reg = tpoint->branch.dynamic_reg & ~JUMP_OP_DYNAMIC_REG_REF;

	if (tpoint->branch.opcode != JUMP_OP_OPCODE_DYNAMIC) {
		return tpoint->branch.to;
	}

	if (!is_ref) {
		long off = reg_to_offset[reg];
		return ptrace(PTRACE_PEEKUSER, pid, off, NULL);
	}

	if (!is_sib) {
		long off;
		if (reg == 32)  /* RIP */
			off = rip;
		else
			off = ptrace(PTRACE_PEEKUSER, pid, reg_to_offset[reg], NULL);
		off += tpoint->branch.dynamic_disp32;
		return ptrace(PTRACE_PEEKDATA, pid, off, NULL);
	}

	printf("Not implemented!\n");
	abort();
}

static int trace_point_read_branch_op(struct pmb_tracepoint *tpoint,
				      kpatch_process_t *child,
				      int pid)
{
	char buf[16];
	int ret, i;

	if (tpoint->branch.opcode)
		return 0;

	ret = kpatch_process_mem_read(child,
				      tpoint->branch.from,
				      buf,
				      tpoint->branch.len);
	if (ret < 0) {
		kplogerror("kpatch_process_mem_read");
		return -1;
	}

	/* restore original part of the instruction */
	memcpy(buf, tpoint->orig, sizeof(tpoint->orig));

	ret = branch_op_decode(&tpoint->branch, buf, tpoint->branch.len);
	if (ret < 0) {
		kperr("branch_op_decode");
		return -1;
	}

	return 0;
}

/* Should pass ptrace_ctx instead */
static void trace_point_execute(struct pmb_tracepoint *tpoint,
				kpatch_process_t *child, int pid, long rip)
{
	long rv;

	rv = trace_point_read_branch_op(tpoint, child, pid);
	if (rv < 0)
		return;

	rip += tpoint->branch.len;
	if (trace_point_check_condition(tpoint, child, pid))
		rip = trace_point_resolve_to(tpoint, child, pid, rip);

	printf("from = %lx, to = %lx\n", tpoint->branch.from, rip);

	rv = ptrace(PTRACE_POKEUSER, pid,
		    offsetof(struct user_regs_struct, rip),
		    (void *)(uintptr_t)rip);

	if (rv == -1) {
		kplogerror("wtf?");
	}
}

static int bsearch_compare(const void *key, const void *mem)
{
	long addr = (long) key;
	const struct pmb_tracepoint *p = mem;

	if (addr < p->branch.from)
		return -1;
	else if (addr == p->branch.from)
		return 0;
	else
		return 1;
}

static int trace_process(kpatch_process_t *child,
			 struct pmb_tracepoint *tpoints,
			 size_t npoints)
{
	int pid;
	long rv;
	size_t i;
	struct pmb_tracepoint *p;
	
	while (1) {
		pid = kpatch_process_execute_until_stop(child);
		/* They are all exited */
		if (pid == 0)
			break;

		rv = ptrace(PTRACE_PEEKUSER, pid,
			    offsetof(struct user_regs_struct, rip),
			    NULL);
		if (rv == -1) {
			perror("ptrace");
			return rv;
		}
		rv--;

		p = bsearch((void *)rv, tpoints, npoints, sizeof(*p),
			    bsearch_compare);
		if (p) {
			trace_point_execute(p, child, pid, rv);
		} else {
			printf("Unexpected stop at %lx\n", rv);
		}
	}

	return 0;
}

int main(int argc, char * const argv[])
{
	struct pmb_tracepoint *tpoints;
	size_t npoints;
	int ret;
	int pid;
	kpatch_process_t child;

	ret = branch_op_read_input_file(argv[1], &tpoints, &npoints);
	if (ret < 0)
		return -1;

	pid = attach_to_process(&child, argv + 2);
	ret = install_trace_points(&child, tpoints, npoints);
	if (ret < 0) {
		fprintf(stderr, "install_trace_points\n");
	}
	trace_process(&child, tpoints, npoints);
}
