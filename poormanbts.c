
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
	long dst = tpoint->jcc.from;

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

static int install_trace_points(kpatch_process_t *child, struct pmb_tracepoint *tpoints, size_t npoints)
{
	int ret = -1;
	struct pmb_tracepoint *p;
	size_t i;

	for (i = 0, p = tpoints; i < npoints; i++, p++) {
		ret = install_trace_point(child, p);
		if (ret < 0)
			goto out;
	}

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

	kpatch_process_init(child, pid, 1, sv[1]);
	kpatch_process_load_libraries(child);
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



static bool trace_point_check_condition(int pid, struct pmb_tracepoint *tpoint)
{
	unsigned long eflags;

	eflags = ptrace(PTRACE_PEEKUSER, pid, offsetof(struct user_regs_struct, eflags), NULL);

#define	FLAG(x)	(eflags & X86_EFLAGS_ ## x)
	switch (tpoint->jcc.opcode) {
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

	case	0x75: /* jne */
		return	!FLAG(ZF);

	case	0x71: /* jno */
		return	!FLAG(OF);

	case	0xe3: /* jcxz/jecxz/jrcxz */
		return	!!ptrace(PTRACE_PEEKUSER, pid,
				 offsetof(struct user_regs_struct, rcx), NULL);

	case	0x7b: /* jnp or jpo */
		return	!FLAG(PF);

	case	0x7a: /* jp or jpe */
		return	FLAG(PF);

	case	0x78: /* js */
		return	FLAG(SF);

	case	0xe9:
	case	0xeb:
	case	JUMP_OP_OPCODE_DYNAMIC:
		/* unconditional jumps */
		return true;
	default:
		printf("unknown opcode %x\n", tpoint->jcc.opcode);
		abort();
	}
}

static long trace_point_resolve_to(int pid, long rip, struct pmb_tracepoint *tpoint)
{
	bool is_ref = tpoint->jcc.dynamic_reg & JUMP_OP_DYNAMIC_REG_REF;
	bool is_sib = tpoint->jcc.dynamic_sib_mult; 
	int reg = tpoint->jcc.dynamic_reg & ~JUMP_OP_DYNAMIC_REG_REF;

	if (tpoint->jcc.opcode != JUMP_OP_OPCODE_DYNAMIC) {
		return tpoint->jcc.to;
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
		off += tpoint->jcc.dynamic_disp32;
		return ptrace(PTRACE_PEEKDATA, pid, off, NULL);
	}

	printf("BROKEN!\n");
	abort();
}

static void trace_point_execute(int pid, long rip, struct pmb_tracepoint *tpoint)
{
	long rv;

	rip += tpoint->jcc.len;
	if (trace_point_check_condition(pid, tpoint))
		rip = trace_point_resolve_to(pid, rip, tpoint);

	printf("from = %lx, to = %lx\n", tpoint->jcc.from, rip);

	rv = ptrace(PTRACE_POKEUSER, pid,
		    offsetof(struct user_regs_struct, rip),
		    (void *)(uintptr_t)rip);

	if (rv == -1) {
		kplogerror("wtf?");
	}
}

static int trace_process(kpatch_process_t *child,
			 struct pmb_tracepoint *tpoints,
			 size_t npoints)
{
	int pid;
	long rv;
	size_t i;
	
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

		for (i = 0; i < npoints; i++) {
			if (rv == tpoints[i].jcc.from) {
				trace_point_execute(pid, rv, &tpoints[i]);
				break;
			}
		}
		if (i == npoints) {
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

	ret = jump_op_read_input_file(argv[1], &tpoints, &npoints);
	if (ret < 0)
		return -1;

	pid = attach_to_process(&child, argv + 2);
	ret = install_trace_points(&child, tpoints, npoints);
	if (ret < 0) {
		fprintf(stderr, "install_trace_points\n");
	}
	trace_process(&child, tpoints, npoints);
}
