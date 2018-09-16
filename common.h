
#ifndef __COMMON_H__
#define __COMMON_H__

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

struct pmb_tracepoint {
	struct jump_op jcc;
	unsigned char orig[1];
};

int jump_op_read_input_file(const char *filename,
			    struct pmb_tracepoint **points,
			    size_t *npoints);

#endif /* __COMMON_H__ */
