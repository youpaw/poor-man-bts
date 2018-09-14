
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "common.h"

/* TODO(pboldin): This code should be a part of objtool-coverage library */
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

int jump_op_read_input_file(const char *filename,
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
		ret = jump_op_parse(&tmp.jcc, buf);
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

