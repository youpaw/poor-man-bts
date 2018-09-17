
#ifndef __KERNEL__
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#else /* ifndef __KERNEL__ */
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#endif /* else ifndef __KERNEL__ */

#include "common.h"

#ifdef __KERNEL__
#define strdup(x)	kstrdup(x, GFP_KERNEL)
#endif

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

#ifndef __KERNEL__
int branch_op_decode(struct branch_op *branch, const char *buf, size_t size)
{
	struct insn insn;

        unsigned char op1, op2, rex = 0, rex_b = 0, rex_r = 0, rex_w = 0,
		      rex_x = 0, modrm = 0, modrm_mod = 0, modrm_rm = 0,
		      modrm_reg = 0, sib = 0;


	/* Parsed already! */
	if (branch->opcode != 0)
		return 0;

	insn_init(&insn, buf, size, /* always x86_64 */1);
	insn_get_length(&insn);

	if (!insn_complete(&insn)) {
		return -1;
	}

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

	switch (op1) {
	case 0xc2: /* return */
	case 0xc3:
		branch->type = INSN_RETURN;
		break;

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
		}
		break;
	case 0xff:
		if (modrm_reg == 2 || modrm_reg == 3) {
			branch->type = INSN_CALL_DYNAMIC;
			goto dynamic_regs;
		} else if (modrm_reg == 4) {
			branch->type = INSN_JUMP_DYNAMIC;
			goto dynamic_regs;
		}
	default:
		branch->to = 0;
		return -1;
	}

	return 0;

dynamic_regs:
	branch->dynamic_reg = modrm_rm + (rex_b << 3);

	if (modrm_mod != 0x3) { /* is mem ref */
		if (modrm_mod == 0 && modrm_rm == 0x5) {
			branch->dynamic_reg = 0x20; /* RIP */
		} else if (modrm_rm == 0x4) { /* is sib ref */
			branch->dynamic_reg = X86_SIB_BASE(sib) + (rex_b << 3);
			branch->dynamic_sib_reg  = X86_SIB_INDEX(sib) + (rex_x << 3);
			branch->dynamic_sib_mult = 1 << X86_SIB_SCALE(sib);
		}

		branch->dynamic_reg |= JUMP_OP_DYNAMIC_REG_REF;
	}

	branch->dynamic_disp32 = insn.displacement.value;
	return 0;
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
