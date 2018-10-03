
#ifndef __KERNEL__
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "eflags.h"
#else /* ifndef __KERNEL__ */
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#endif /* else ifndef __KERNEL__ */

#include "common.h"

#ifdef __KERNEL__
#define strdup(x)	kstrdup(x, GFP_KERNEL)
#endif

int
branch_op_check_condition(struct branch_op *branch,
			  unsigned long eflags,
			  unsigned long rcx)
{
#define	FLAG(x)	(eflags & X86_EFLAGS_ ## x)
	switch (branch->opcode) {
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
		return !!rcx;

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
		return	1;
	default:
		return -EINVAL;
	}
}

long
branch_op_resolve_to(struct branch_op *branch,
		     long (*read_reg)(int reg, void *arg),
		     long (*read_mem)(long mem, void *arg),
		     void *arg)
{
	int is_ref = branch->dynamic_reg & JUMP_OP_DYNAMIC_REG_REF;
	int is_sib = branch->dynamic_sib_mult;
	int reg = branch->dynamic_reg & ~JUMP_OP_DYNAMIC_REG_REF;

	if (branch->opcode != JUMP_OP_OPCODE_DYNAMIC) {
		return branch->to;
	}

	if (!is_ref)
		return read_reg(reg, arg);

	if (!is_sib) {
		long off = 0;
		if (reg != REG_NONE)
			off = read_reg(reg, arg);
		off += (long)branch->dynamic_disp32;
		return read_mem(off, arg);
	} else {
		long base = 0, index = 0, off = (long)branch->dynamic_disp32;
		if (reg != REG_NONE)
			base = read_reg(reg, arg);
		if (branch->dynamic_sib_reg != REG_NONE)
			index = read_reg(branch->dynamic_sib_reg, arg);

		off += base + index * branch->dynamic_sib_mult;

		return read_mem(off, arg);
	}

#ifndef __KERNEL__
	errno = -EINVAL;
#endif
	return -1;
}


/* returns -1 on error, 1 when branch op is found, 0 otherwise.
 * updates pbuf accordingly, may be used to got through functions */
int branch_op_decode(struct branch_op *branch, const char **pbuf, size_t size)
{
	struct insn insn;

        unsigned char op1, op2, rex = 0, rex_b = 0, rex_r = 0, rex_w = 0,
		      rex_x = 0, modrm = 0, modrm_mod = 0, modrm_rm = 0,
		      modrm_reg = 0, sib = 0;


	/* Parsed already! */
	if (branch->opcode != 0)
		return 1;

	insn_init(&insn, *pbuf, size, /* always x86_64 */1);
	insn_get_length(&insn);

	if (!insn_complete(&insn))
		return -1;

	(*pbuf) += insn.length;

	op1 = insn.opcode.bytes[0];
	op2 = insn.opcode.bytes[1];

	if (insn.rex_prefix.nbytes) {
		rex = insn.rex_prefix.bytes[0];
		rex_w = X86_REX_W(rex) >> 3;
		rex_r = X86_REX_R(rex) >> 2;
		rex_x = X86_REX_X(rex) >> 1;
		rex_b = X86_REX_B(rex);
	}

	if (insn.modrm.nbytes) {
		modrm = insn.modrm.bytes[0];
		modrm_mod = X86_MODRM_MOD(modrm);
		modrm_reg = X86_MODRM_REG(modrm);
		modrm_rm = X86_MODRM_RM(modrm);
	}

	if (insn.sib.nbytes)
		sib = insn.sib.bytes[0];

	/* defaults */
	branch->to = branch->from + insn.length + insn.immediate.value;
	branch->opcode = op1;
	branch->len = insn.length;

	switch (op1) {
	case 0xe8: /* call */
		branch->type = INSN_CALL;
		break;
	case 0xe9: /* dumb jumps */
	case 0xeb:
		branch->type = INSN_JUMP_UNCONDITIONAL;
		break;
	case 0xe3: /* ecx jumps */
	case 0x70 ... 0x7f: /* cond jumps */
		branch->type = INSN_JUMP_CONDITIONAL;
		break;
	case 0x0f:
		if (op2 >= 0x80 && op2 <= 0x8f) {
			branch->type = INSN_JUMP_CONDITIONAL;
			branch->opcode = op2 - 0x10;
			break;
		}

		return 0;
	case 0xff:
		if (modrm_reg == 2 || modrm_reg == 3) {
			branch->type = INSN_CALL_DYNAMIC;
			goto dynamic_regs;
		} else if (modrm_reg == 4) {
			branch->type = INSN_JUMP_DYNAMIC;
			goto dynamic_regs;
		}
		/* fallthrough */
	default:
		branch->opcode = 0;
		return 0;
	}

	return 1;

dynamic_regs:
	branch->to = 0;
	branch->dynamic_reg = modrm_rm + (rex_b << 3);

	/* SDM Vol. 2, Table 2-2 */
	if (modrm_mod != 0x3) {
		/* RIP-relative addressing, Table 2-7 */
		if (modrm_mod == 0 && modrm_rm == 0x5) {
			branch->dynamic_reg = REG_RIP;
		}
		/* SIB byte, Table 2-3 */
		else if (modrm_rm == 0x4) {
			branch->dynamic_reg = X86_SIB_BASE(sib) + (rex_b << 3);
			if (branch->dynamic_reg == 0x5 && modrm_mod == 0)
				branch->dynamic_reg = REG_NONE;
			branch->dynamic_sib_reg  = X86_SIB_INDEX(sib) + (rex_x << 3);
			if (branch->dynamic_sib_reg == 0x4)
				branch->dynamic_sib_reg = REG_NONE;
			branch->dynamic_sib_mult = 1 << X86_SIB_SCALE(sib);
		}

		branch->dynamic_reg |= JUMP_OP_DYNAMIC_REG_REF;
	}

	branch->dynamic_disp32 = insn.displacement.value;
	return 1;
}

#ifndef __KERNEL__
/* TODO(pboldin) these are not so common, move them */
static int branch_op_parse(struct branch_op *branch,
			   const char *in)
{
	int ret;

	memset(branch, 0, sizeof(*branch));
	ret = sscanf(in, "0x%lx+0x%x", &branch->from, &branch->len);

	if (ret != 2)
		return -1;

	return 0;
}

int parse_trace_point_line(const char *buf,
			   struct pmb_tracepoint *point)
{
	char *p;
	const char objname_str[] = "objname=";
	const size_t objname_str_len = sizeof(objname_str) - 1;
	static char *objname;
	int ret;

	p = strstr(buf, objname_str);
	if (p) {
		p += objname_str_len;
		objname = strdup(p);
	}

	p = strchr(buf, '#');
	if (p == buf)
		return 0;

	if (p)
		*p = '\0';

	ret = branch_op_parse(&point->branch, buf);
	if (ret < 0) {
		return -1;
	}
	point->objname = objname;

	return 1;
}


int branch_op_read_input_file(const char *filename,
			      struct pmb_tracepoint **points,
			      size_t *npoints)
{
	FILE *fh;
	char buf[1024], *p;
	struct pmb_tracepoint *t = NULL, tmp;
	size_t n = 0, nalloc = 0;
	int ret = -1;

	tmp.objname = NULL;

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
		if (fgets(buf, sizeof(buf), fh) == NULL) {
			if (errno == 0)
				break;

			goto out_err;
		}

		buf[strlen(buf) - 1] = '\0';

		ret = parse_trace_point_line(buf, &tmp);
		if (ret < 0)
			goto out_err;
		if (ret == 0)
			continue;

		if (n + 1 > nalloc) {
			struct pmb_tracepoint *newt;

			nalloc += 1024;
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

	ret = 0;
out_err:
	if (ret < 0)
		free(t);
	if (fh != stdin)
		fclose(fh);
	return ret;
}
#endif /* ifndef __KERNEL__ */
