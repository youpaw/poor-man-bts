
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

#include "eflags.h"

#include "kpatch_process.h"
#include "kpatch_log.h"

struct jump_op {
#define JUMP_OP_OPCODE_DYNAMIC	0xff
	unsigned int opcode;

	unsigned long from;
	unsigned int len;
	unsigned long to;

#define JUMP_OP_DYNAMIC_REG_REF	0x80
	unsigned int dynamic_reg;
	unsigned int dynamic_sib_mult;
	unsigned int dynamic_sib_reg;

	unsigned int dynamic_disp32;
};


/* TODO(pboldin): This code should be a part of objtool-coverage library */
static int parse_jump_op(struct jump_op *jcc,
			 const char *in)
{
	int ret, len;
	const char *p = in;

	memset(jcc, 0, sizeof(*jcc));
	ret = sscanf(p, "0x%x 0x%lx+0x%x %n",
		     &jcc->opcode,
		     &jcc->from,
		     &jcc->len,
		     &len);
	if (ret != 3)
		return -1;

	p += len;

	ret = sscanf(p, "0x%lx", &jcc->to);
	if (ret == 1)
		return 0;

	ret = sscanf(p, "*0x%x(%d, %d, %d)",
		     &jcc->dynamic_disp32,
		     &jcc->dynamic_reg,
		     &jcc->dynamic_sib_reg,
		     &jcc->dynamic_sib_mult);
	if (ret == 4)
		goto check_dynamic_ref;

	ret = sscanf(p, "*0x%x(%d)",
		     &jcc->dynamic_disp32,
		     &jcc->dynamic_reg);
	if (ret == 2)
		goto check_dynamic_ref;

	ret = sscanf(p, "*%d",
		     &jcc->dynamic_reg);
	if (ret == 1)
		goto check_dynamic_jump;

	return -1;

check_dynamic_ref:
	jcc->dynamic_reg |= JUMP_OP_DYNAMIC_REG_REF;
check_dynamic_jump:
	if (jcc->opcode != JUMP_OP_OPCODE_DYNAMIC)
		return -1;

	return 0;
}

struct tracepoint {
	struct jump_op jcc;
	void *origcode;
};

static int read_input_file(const char *filename,
			   struct tracepoint **points,
			   size_t *npoints)
{
	FILE *fh;
	char buf[1024];
	struct tracepoint *t = NULL, tmp;
	size_t n = 0, nalloc = 0;
	int ret;

	*points = NULL;
	*npoints = 0;

	if (!strcmp(filename, "-"))
		fh = stdin;
	else
		fh = fopen(filename, "r");

	if (fh == NULL) {
		perror("fopen");
		return -1;
	}

	while (!feof(fh)) {
		fgets(buf, sizeof(buf), fh);
		ret = parse_jump_op(&tmp.jcc, buf);
		if (ret < 0) {
			fprintf(stderr, "can't parse %s\n", buf);
			goto out_err;
		}

		if (n + 1 > nalloc) {
			struct tracepoint *newt;

			nalloc = nalloc ? nalloc * 2 : 16;
			newt = realloc(t, sizeof(*t) * nalloc);
			if (newt == NULL) {
				ret = -1;
				goto out_err;
			}

			t = newt;
		}

		t[n] = tmp;
		n++;
	}

	*points = t;
	*npoints = n;

out_err:
	if (ret < 0)
		free(t);
	if (fh != stdin)
		fclose(fh);
	return ret;
}

static int install_trace_points(kpatch_process_t *child, struct tracepoint *tpoints, size_t npoints)
{
	int memfd = child->memfd, ret = -1;
	char path[1024];
	struct tracepoint *p;
	size_t i;

	for (i = 0, p = tpoints; i < npoints; i++, p++) {
		ret = pwrite(memfd, "\xcc", 1, p->jcc.from);
		if (ret < 0)
			perror("pwrite");
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



static bool trace_point_check_condition(int pid, struct tracepoint *tpoint)
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

static long trace_point_resolve_to(int pid, long rip, struct tracepoint *tpoint)
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

static void trace_point_execute(int pid, long rip, struct tracepoint *tpoint)
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
			 struct tracepoint *tpoints,
			 size_t npoints)
{
	int pid;
	long rv;
	size_t i;
	
	while (1) {
		pid = kpatch_process_execute_until_stop(child);

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
}

int main(int argc, char * const argv[])
{
	struct tracepoint *tpoints;
	size_t npoints;
	int ret;
	int pid;
	kpatch_process_t child;

	ret = read_input_file(argv[1], &tpoints, &npoints);
	if (ret < 0)
		return -1;

	pid = attach_to_process(&child, argv + 2);
	ret = install_trace_points(&child, tpoints, npoints);
	if (ret < 0) {
		fprintf(stderr, "install_trace_points\n");
	}
	trace_process(&child, tpoints, npoints);
}
