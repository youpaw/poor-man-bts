
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

static int jump_op_parse(struct jump_op *jcc,
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

int parse_trace_point_line(const char *buf, struct pmb_tracepoint *point)
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

	ret = jump_op_parse(&point->jcc, buf);
	if (ret < 0) {
		return -1;
	}
	point->objname = objname;

	return 1;
}

#ifndef __KERNEL__
int jump_op_read_input_file(const char *filename,
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
